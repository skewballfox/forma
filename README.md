# Forma

An Extension for Materia for managing image updates and system permissions. 

Materia is a gitops tool for managing and deploying systemd quadlets. This is an extension meant for managing the images and system permissions for running those quadlets with minimal trust.

## Key Features (Planned)
- create, manage, and remove: 
  - users, groups, and permissions for Materia managed quadlets
  - udev rules
  - selinux container policies on supported systems
  - (maybe/eventually) firewall rules
- Build and sign images in a dedicated account
  - images are readonly for the created accounts
  - signed images are enforced for the managed accounts, irrespective of the system policy. 
  - the builder account relies on buildah and has no extra permissions. 
- transactional record and system aware:
  - i.e. it won't accidentally delete a user or group that it did not create  
  

## Getting Started
TODO: draw the rest of the owl

