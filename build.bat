SET i=%CD%
SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% )
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DQRYPTEXT_ENABLE_PROGRAMS=On -DQRYPTEXT_ENABLE_TESTS=Off -DCMAKE_BUILD_TYPE=Release ..
msbuild ALL_BUILD.vcxproj /p:configuration=release
msbuild programs\ALL_BUILD.vcxproj /p:configuration=release
mkdir include\qryptext
xcopy ..\include\qryptext .\include\qryptext
tar -czvf qryptext.tar.gz include\qryptext\* Release\* programs\Release\*.exe
cd %i%