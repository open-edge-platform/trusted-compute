## Go and C Debugging
Visual Studio Code's 'Remote Development' extension provides go/c debugging in the 'tpm-devel' container (using the Microsoft TPM simulator).

To run these steps, you must install Docker and the 'Remote Development' extension.

1. Create a new `tpm-devel` container (see [Compiling tpm-provider](build.md#Compiling-tpm-provider) for instructions on creating a `tpm-devel` container).
    * cd to the root of the project directory -- the current dir will be mounted as /docker_host in the container.
    * Run `docker run -d --rm -v $(pwd):/docker_host -p 1443:1443 --name=tpm-devel tpm-devel tail -f /dev/null`
2. Go to vscode's docker tab, right click on the new container and select 'Attach Visual Studio Code'.  A new vscode window will open.  Open the '/docker_host' folder which is the local source repo mounted in the container.
3. In the new vscode window, install the C++ and Go extensions (i.e. they will be installed for debugging on the container). 
4. Add the following debug configuration to `.vscode/launch.json` that will launch '`tagent setup takeownership`'.
    ```
    {
        "name": "GTA: (gdb) Launch",
        "type": "cppdbg",
        "request": "launch",
        "program": "${workspaceFolder}/go-trust-agent/out/tagent",
        "args": ["setup", "takeownership"],
        "stopAtEntry": false,
        "cwd": "${workspaceFolder}/go-trust-agent/out/",
        "environment": [],
        "externalConsole": false,
        "MIMode": "gdb",
        "setupCommands": [
            {
                "description": "Enable pretty-printing for gdb",
                "text": "-enable-pretty-printing",
                "ignoreFailures": true
            }
        ]
    }
    ```
5. Build GTA in the debug container (i.e. `make` from the go-trust-agent directory).  * Note: This requires that git configuration and ssh keys.*
6. Debug:  Set breakpoints in go or C code, use to vscode's debug tab and select the name of the target (in this case 'GTA:(gdb) Launch').  Click the 'Start Debugging' button.  Repeat setps 5 and 6 as needed.