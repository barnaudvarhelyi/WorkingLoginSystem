@echo off

set ExeName=test

set GOOS=windows

if not exist .\build (
    mkdir .\build
)

if exist .\build\%ExeName%.exe (
    del .\build\%ExeName%.exe
)

go build -v -o .\build\%ExeName%.exe

if exist .\build\%ExeName%.exe (
    pushd .\build
    .\%ExeName%.exe
    popd
)