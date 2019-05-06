## Compiling Scylla
To compile Scylla you need to have atleast [VS2017 installed](https://visualstudio.microsoft.com/downloads/).

The dependencies are fetched using git submodules. When your source tree is missing the submodules just run ```git submodule -q update --init``` in the root directory.

To build Scylla either open the CMakeLists.txt file in Visual Studio or use the command line.

To build from a powershell simply run

```powershell
New-Item -Force -Path "./build" -ItemType Directory
cd "./build"
cmake -A "x64" -DCMAKE_INSTALL_PREFIX:PATH="../install" -DCMAKE_BUILD_TYPE="Release" -DVERSION_TCHAR="0.0.0" -DVERSION_DWORD="00000000" ..
cmake --build . --config "Release"
cmake --build . --config "Release" --target install
```
