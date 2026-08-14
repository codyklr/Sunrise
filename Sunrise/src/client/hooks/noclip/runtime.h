#pragma once

namespace sunrise::client::hooks::noclip {

/**
 * Resolves the Havok targets and attaches the independent simulation-step detour.
 * @return True when both signatures resolve and the detour is attached.
 */
[[nodiscard]] bool install() noexcept;

/** Detaches the simulation-step detour and clears runtime state. */
void uninstall() noexcept;

/** Clears the active toggle and horizontal target. */
void reset() noexcept;

/** @return True while horizontal noclip is toggled on. */
[[nodiscard]] bool active() noexcept;

/** Invalidates the horizontal target after another feature changes rigid-body position. */
void invalidate_target() noexcept;

} // namespace sunrise::client::hooks::noclip
