::
::    Copyright 2020 Raphael Beck
::
::    Licensed under the Apache License, Version 2.0 (the "License");
::    you may not use this file except in compliance with the License.
::    You may obtain a copy of the License at
::
::        http://www.apache.org/licenses/LICENSE-2.0
::
::    Unless required by applicable law or agreed to in writing, software
::    distributed under the License is distributed on an "AS IS" BASIS,
::    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
::    See the License for the specific language governing permissions and
::    limitations under the License.
::

SET repo=%~dp0
SET out="%repo%\build-msvc"
if exist %out% ( rd /s /q %out% ) 
mkdir %out% && cd %out%
cmake -DBUILD_SHARED_LIBS=Off -DQRYPTEXT_ENABLE_TESTS=On -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
call Debug\run_tests.exe
cd ..
