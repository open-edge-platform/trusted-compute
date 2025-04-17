# Attestation Manager

## Overview
The Attestation Manager is a tool designed to manage and verify attestations in a trusted computing environment. It ensures the integrity and authenticity of the system components.

## Features
- Manage attestations
- Verify integrity and authenticity 

## Installation
To install the Attestation Manager, clone the repository and install the dependencies(go,docker):

```sh
git clone  https://github.com/open-edge-platform/trusted-compute.git
cd attestation-manager

## to build AM binary 
make build

## to build docker image
docker build -t <image-name>:<tag> .
```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
For any questions or feedback, please contact us at prashant.sholapur@intel.com.
