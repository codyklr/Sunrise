/**
 * Noclip at the Havok simulation boundary. Ordinary mode replaces collision-resolved X/Y
 * position. Fly mode owns all three position lanes and clears native velocity after simulation.
 */

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/ui/runtime/ui_visibility_runtime.h"
#include "../../../state/account/account_state.h"
#include "../../../state/runtime/runtime.h"
#include "../../hooking/detour.h"
#include "../../patterns/image_scan.h"
#include "../../teleport/teleport_settings_store.h"
#include "../teleport/runtime.h"
#include "runtime.h"

namespace sunrise::client::hooks::noclip {
namespace {

/** hkpSimulation::stepDeltaTime, which encloses Havok integration and collision resolution. */
constexpr std::string_view kHavokStepText =
    "40 53 48 83 EC 20 83 79 38 01 48 8B D9 77 06 48 8B 01 FF 50 20 F7 43 38 FD FF FF FF "
    "75 09 48 8B 03 48 8B CB FF 50 28";
constexpr auto kHavokStep =
    patterns::signature<patterns::signature_length(kHavokStepText)>(kHavokStepText);

/** Constructs hkpCharacterMotion and loads its vtable through the leading RIP-relative LEA. */
constexpr std::string_view kCharacterMotionVtableText = "48 8D 05 ? ? ? ? C6 43 ? ? 48 89 03 EB";
constexpr auto kCharacterMotionVtable =
    patterns::signature<patterns::signature_length(kCharacterMotionVtableText)>(
        kCharacterMotionVtableText);

/** RIP-relative displacement and instruction-end offsets in the vtable LEA. */
constexpr std::size_t kVtableDisplacement = 3;
constexpr std::size_t kVtableInstructionLength = 7;

/** hkpSimulation::m_world. */
constexpr std::size_t kSimulationWorld = 0x18;
/** hkpWorld simulation-island arrays. */
constexpr std::array<std::size_t, 2> kWorldIslandArrays{0x40, 0x50};
/** hkpSimulationIsland::m_entities. */
constexpr std::size_t kIslandEntities = 0x60;
/** hkpRigidBody's embedded hkpMotion object. */
constexpr std::size_t kBodyMotion = 0x150;
/** World position and linear velocity in the embedded motion. */
constexpr std::size_t kBodyPosition = 0x1C0;
constexpr std::size_t kBodyVelocity = 0x230;

/** X and Y are Destiny's horizontal world-space lanes. */
constexpr std::size_t kHorizontalX = 0;
constexpr std::size_t kHorizontalY = 1;
constexpr std::size_t kVectorLanes = 4;

/**
 * Havok stores ownership flags in the upper two capacity bits. Masking them leaves the allocation
 * capacity used to validate an hkArray before walking it.
 */
constexpr std::uint32_t kArrayCapacityMask = 0x3FFFFFFF;
/** Defensive limits for game-owned island and entity arrays. */
constexpr std::int32_t kMaximumIslandCount = 4096;
constexpr std::int32_t kMaximumEntityCount = 65536;
/** Maximum accepted physics step; a resumed or stalled frame must not produce a large jump. */
constexpr float kMaximumStepSeconds = 0.05F;
/** Native velocity below this magnitude is treated as stationary. */
constexpr float kMinimumVelocitySquared = 0.000001F;
/** Horizontal camera direction must have this magnitude before it can be normalised. */
constexpr float kMinimumHeadingSquared = 0.000001F;

using HavokStep = std::int32_t(__fastcall*)(std::byte*, float);

struct HavokArray {
    std::byte** entries{};
    std::int32_t size{};
    std::uint32_t capacityAndFlags{};
};

static_assert(sizeof(HavokArray) == 16);

std::atomic_bool g_installed{false};
std::atomic_bool g_active{false};
std::atomic_bool g_toggleDown{false};
std::atomic_bool g_targetValid{false};
std::atomic_bool g_flyMode{false};
/** The two horizontal target floats are one atomic publication, so readers never observe mixed coordinates. */
std::atomic<std::uint64_t> g_horizontalTarget{};
/** Vertical target lane published independently from the horizontal pair. */
std::atomic<std::uint32_t> g_verticalTarget{};
/** Module-owned vtable target; unlike Havok objects, its address is stable until DLL teardown. */
std::uintptr_t g_characterMotionVtable{};
hooking::detour::Handle g_stepHandle{};

/** Views one field while its owning Havok object is live inside the simulation hook. */
template <typename T> [[nodiscard]] T& field(std::byte* object, std::size_t offset) noexcept {
    return *reinterpret_cast<T*>(object + offset);
}

/** @return True when the array header is internally consistent and within the supplied bound. */
[[nodiscard]] bool valid_array(const HavokArray& array, std::int32_t maximum) noexcept {
    const std::uint32_t capacity = array.capacityAndFlags & kArrayCapacityMask;
    return array.size >= 0 && array.size <= maximum
           && static_cast<std::uint32_t>(array.size) <= capacity
           && (array.size == 0 || array.entries != nullptr);
}

/** @return The character rigid body in one island, or null when the island has none. */
[[nodiscard]] std::byte* character_body_in(std::byte* island) noexcept {
    if (island == nullptr) {
        return nullptr;
    }
    const HavokArray& entities = field<HavokArray>(island, kIslandEntities);
    if (!valid_array(entities, kMaximumEntityCount)) {
        return nullptr;
    }
    for (std::int32_t index = 0; index < entities.size; ++index) {
        std::byte* const body = entities.entries[index];
        if (body != nullptr
            && field<std::uintptr_t>(body, kBodyMotion) == g_characterMotionVtable) {
            return body;
        }
    }
    return nullptr;
}

/** @return The current character rigid body, resolved fresh from active and inactive islands. */
[[nodiscard]] std::byte* character_body(std::byte* simulation) noexcept {
    if (simulation == nullptr) {
        return nullptr;
    }
    std::byte* const world = field<std::byte*>(simulation, kSimulationWorld);
    if (world == nullptr) {
        return nullptr;
    }
    for (const std::size_t offset : kWorldIslandArrays) {
        const HavokArray& islands = field<HavokArray>(world, offset);
        if (!valid_array(islands, kMaximumIslandCount)) {
            continue;
        }
        for (std::int32_t index = 0; index < islands.size; ++index) {
            std::byte* const island = islands.entries[index];
            if (std::byte* const body = character_body_in(island); body != nullptr) {
                return body;
            }
        }
    }
    return nullptr;
}

/** Packs the horizontal target into one atomic value. */
[[nodiscard]] std::uint64_t pack_target(float x, float y) noexcept {
    return std::bit_cast<std::uint64_t>(std::array<float, 2>{x, y});
}

/** Unpacks one atomically published horizontal target. */
[[nodiscard]] std::array<float, 2> unpack_target(std::uint64_t value) noexcept {
    return std::bit_cast<std::array<float, 2>>(value);
}

/** @return True when either half of an authored game binding is currently held. */
[[nodiscard]] bool binding_down(const state::account::settings::bindings::Binding& binding) noexcept {
    const auto down = [](const std::optional<std::uint16_t>& authored) noexcept {
        return authored.has_value()
               && hooks::teleport::action_key(*authored) != 0
               && (GetAsyncKeyState(static_cast<int>(hooks::teleport::action_key(*authored))) & 0x8000) != 0;
    };
    return down(binding.primary) || down(binding.secondary);
}

/** Builds a normalised three-dimensional free-flight direction from configured game bindings. */
[[nodiscard]] std::array<float, 3> flight_direction() noexcept {
    if (core::ui::runtime::snapshot().visible) {
        return {};
    }
    const state::AccountState account = state::account_snapshot();
    using Action = state::account::settings::bindings::Action;
    const auto held = [&account](Action action) noexcept {
        return binding_down(account.settings.keyBindings.values[static_cast<std::size_t>(action)]);
    };
    const float forward = (held(Action::moveForward) ? 1.0F : 0.0F)
                          - (held(Action::moveBackward) ? 1.0F : 0.0F);
    const float strafe = (held(Action::moveRight) ? 1.0F : 0.0F)
                         - (held(Action::moveLeft) ? 1.0F : 0.0F);
    // The default crouch binding is Control. Keep that direct fallback because the game may
    // consume the authored toggle action before this post-simulation hook polls it.
    const bool crouching = held(Action::toggleCrouch) || held(Action::holdCrouch)
                            || (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    const float vertical = (held(Action::jump) ? 1.0F : 0.0F) - (crouching ? 1.0F : 0.0F);
    std::array<float, 3> direction{0.0F, 0.0F, vertical};
    std::array<float, 2> camera{};
    if ((forward != 0.0F || strafe != 0.0F)
        && hooks::teleport::horizontal_camera_forward(camera)) {
        const float headingSquared = camera[0] * camera[0] + camera[1] * camera[1];
        if (headingSquared > kMinimumHeadingSquared) {
            const float inverseLength = 1.0F / std::sqrt(headingSquared);
            const float forwardX = camera[0] * inverseLength;
            const float forwardY = camera[1] * inverseLength;
            // Destiny's horizontal basis uses the opposite handedness from the conventional
            // XY cross-product, so this is the player's right vector rather than its left.
            direction[0] += forwardX * forward + forwardY * strafe;
            direction[1] += forwardY * forward - forwardX * strafe;
        }
    }
    const float lengthSquared = direction[0] * direction[0] + direction[1] * direction[1]
                                + direction[2] * direction[2];
    if (lengthSquared <= 0.0F) {
        return {};
    }
    const float inverseLength = 1.0F / std::sqrt(lengthSquared);
    for (float& lane : direction) {
        lane *= inverseLength;
    }
    return direction;
}

/** Polls the configured edge-triggered toggle on the physics thread. */
void poll_toggle() noexcept {
    const client::teleport::Settings settings = client::teleport::get();
    const bool usable =
        settings.noclipEnabled && settings.noclipToggleKey != client::teleport::kNoKey;
    const bool down =
        usable && (GetAsyncKeyState(static_cast<int>(settings.noclipToggleKey)) & 0x8000) != 0;
    if (!usable) {
        g_toggleDown.store(false, std::memory_order_relaxed);
        if (g_active.exchange(false, std::memory_order_acq_rel)) {
            invalidate_target();
        }
        return;
    }
    if (core::ui::runtime::snapshot().visible) {
        g_toggleDown.store(down, std::memory_order_relaxed);
        return;
    }
    if (down && !g_toggleDown.exchange(true, std::memory_order_acq_rel)) {
        const bool enabled = !g_active.load(std::memory_order_acquire);
        g_active.store(enabled, std::memory_order_release);
        invalidate_target();
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         enabled ? "ev=noclip stage=toggle active=1 mode=rigid_body_position"
                                 : "ev=noclip stage=toggle active=0 mode=rigid_body_position");
        return;
    }
    if (!down) {
        g_toggleDown.store(false, std::memory_order_release);
    }
}

/** Runs Havok normally, then applies horizontal noclip or a full three-dimensional flight target. */
std::int32_t __fastcall havok_step(std::byte* simulation, float deltaTime) noexcept {
    poll_toggle();
    const client::teleport::Settings settings = client::teleport::get();
    const bool flying = settings.noclipFlyEnabled;
    if (flying != g_flyMode.exchange(flying, std::memory_order_acq_rel)) {
        invalidate_target();
    }

    std::array<float, kVectorLanes> nativeVelocity{};
    const bool enabledBeforeStep = active();
    std::byte* const before = enabledBeforeStep ? character_body(simulation) : nullptr;
    const bool hasVelocity = before != nullptr;
    if (hasVelocity && !flying) {
        nativeVelocity = field<std::array<float, kVectorLanes>>(before, kBodyVelocity);
    }

    const HavokStep next = reinterpret_cast<HavokStep>(g_stepHandle.original);
    const std::int32_t result = next != nullptr ? next(simulation, deltaTime) : 0;

    if (!enabledBeforeStep || !active()) {
        return result;
    }
    std::byte* const body = character_body(simulation);
    if (body == nullptr) {
        // Other Havok worlds do not contain the player and must not disturb the shared target.
        // Only a world that contained the character before this step can prove it was removed.
        if (before != nullptr) {
            invalidate_target();
        }
        return result;
    }
    std::array<float, kVectorLanes> position =
        field<std::array<float, kVectorLanes>>(body, kBodyPosition);
    // A character created or replaced during this step has no compatible velocity or target.
    if (before == nullptr || body != before) {
        invalidate_target();
    }
    if (!g_targetValid.load(std::memory_order_acquire)) {
        g_horizontalTarget.store(pack_target(position[kHorizontalX], position[kHorizontalY]),
                                 std::memory_order_relaxed);
        g_verticalTarget.store(std::bit_cast<std::uint32_t>(position[2]), std::memory_order_relaxed);
        g_targetValid.store(true, std::memory_order_release);
        return result;
    }

    const float step = std::clamp(deltaTime, 0.0F, kMaximumStepSeconds);
    if (flying) {
        const std::array<float, 3> direction = flight_direction();
        const std::array<float, 2> target =
            unpack_target(g_horizontalTarget.load(std::memory_order_acquire));
        const float speed = settings.noclipFlySpeed * step;
        const float targetX = target[kHorizontalX] + direction[0] * speed;
        const float targetY = target[kHorizontalY] + direction[1] * speed;
        const float targetZ = std::bit_cast<float>(g_verticalTarget.load(std::memory_order_acquire))
                              + direction[2] * speed;
        position[kHorizontalX] = targetX;
        position[kHorizontalY] = targetY;
        position[2] = targetZ;
        field<std::array<float, kVectorLanes>>(body, kBodyPosition) = position;
        // No native velocity is retained in Fly mode, so gravity and collision cannot pull the
        // target back between steps when no movement key is held.
        field<std::array<float, kVectorLanes>>(body, kBodyVelocity) = {};
        g_horizontalTarget.store(pack_target(targetX, targetY), std::memory_order_release);
        g_verticalTarget.store(std::bit_cast<std::uint32_t>(targetZ), std::memory_order_release);
        return result;
    }

    if (!hasVelocity) {
        return result;
    }
    const float velocitySquared = nativeVelocity[kHorizontalX] * nativeVelocity[kHorizontalX]
                                  + nativeVelocity[kHorizontalY] * nativeVelocity[kHorizontalY];
    if (step <= 0.0F || velocitySquared <= kMinimumVelocitySquared) {
        return result;
    }
    const std::array<float, 2> target =
        unpack_target(g_horizontalTarget.load(std::memory_order_acquire));
    const float targetX = target[kHorizontalX] + nativeVelocity[kHorizontalX] * step;
    const float targetY = target[kHorizontalY] + nativeVelocity[kHorizontalY] * step;
    position[kHorizontalX] = targetX;
    position[kHorizontalY] = targetY;
    field<std::array<float, kVectorLanes>>(body, kBodyPosition) = position;

    // Collision may consume horizontal velocity before publication. Restore the pre-simulation
    // velocity so the next step keeps advancing the target, while retaining resolved vertical
    // velocity for ordinary ground movement and gravity.
    std::array<float, kVectorLanes> wakeVelocity =
        field<std::array<float, kVectorLanes>>(body, kBodyVelocity);
    wakeVelocity[kHorizontalX] = nativeVelocity[kHorizontalX];
    wakeVelocity[kHorizontalY] = nativeVelocity[kHorizontalY];
    field<std::array<float, kVectorLanes>>(body, kBodyVelocity) = wakeVelocity;
    g_horizontalTarget.store(pack_target(targetX, targetY), std::memory_order_release);
    return result;
}

/** @param reason Stable diagnostic key for an installation failure. */
void report_install_failure(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=noclip stage=install result=fail reason=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

} // namespace

bool install() noexcept {
    if (g_installed.load(std::memory_order_acquire)) {
        return true;
    }
    std::byte* const step = patterns::scan_main_image_unique(kHavokStep, "noclip_havok_step");
    if (step == nullptr) {
        report_install_failure("havok_step");
        return false;
    }
    std::byte* const vtableLoad =
        patterns::scan_main_image_unique(kCharacterMotionVtable, "noclip_character_motion");
    if (vtableLoad == nullptr) {
        report_install_failure("character_motion");
        return false;
    }
    g_characterMotionVtable = reinterpret_cast<std::uintptr_t>(patterns::resolve_relative(
        vtableLoad + kVtableDisplacement, vtableLoad + kVtableInstructionLength));
    if (!hooking::detour::install(hooking::detour::Spec{step, reinterpret_cast<void*>(&havok_step)},
                                  g_stepHandle)) {
        g_characterMotionVtable = 0;
        report_install_failure("attach");
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=noclip stage=install result=ok");
    return true;
}

void uninstall() noexcept {
    if (!g_installed.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    (void)hooking::detour::uninstall(g_stepHandle);
    g_stepHandle = {};
    g_characterMotionVtable = 0;
    reset();
}

void reset() noexcept {
    g_active.store(false, std::memory_order_release);
    g_toggleDown.store(false, std::memory_order_release);
    g_flyMode.store(false, std::memory_order_release);
    g_horizontalTarget.store(0, std::memory_order_release);
    g_verticalTarget.store(0, std::memory_order_release);
    invalidate_target();
}

bool active() noexcept {
    return g_active.load(std::memory_order_acquire);
}

void invalidate_target() noexcept {
    g_targetValid.store(false, std::memory_order_release);
}

} // namespace sunrise::client::hooks::noclip
