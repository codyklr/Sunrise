@echo off
setlocal

rem Syncs this fork's master with upstream (Confetti3/Sunrise) by rebasing local
rem commits on top of the latest upstream master, then pushing to your fork.
rem
rem This keeps your personal changes (dev tools, noclip, fly mode) on top of the
rem latest upstream work. Run it from the repo root.

echo Fetching upstream changes...
git fetch upstream
if errorlevel 1 exit /b %errorlevel%

echo Rebasing master onto upstream/master...
git rebase upstream/master
if errorlevel 1 (
    echo.
    echo Rebase failed. Resolve the conflicts, then run:
    echo   git rebase --continue
    echo   git push --force-with-lease origin master
    exit /b 1
)

echo Pushing to your fork...
git push --force-with-lease origin master
if errorlevel 1 exit /b %errorlevel%

echo.
echo Sync complete. Your fork master is now upstream/master plus your changes.
endlocal