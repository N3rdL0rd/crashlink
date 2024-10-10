@echo off

rmdir /s /q build
rmdir /s /q dist
rmdir /s /q crashlink.egg-info

env\Scripts\python -m build

rmdir /s /q build
rmdir /s /q crashlink.egg-info