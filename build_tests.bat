@echo off
setlocal enabledelayedexpansion

pushd tests\haxe
for %%f in (*.hx) do (
    set "filename=%%~nf"
    haxe -hl !filename!.hl -main !filename!.hx
)
popd

endlocal
