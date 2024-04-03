# Windows Authentication in Containers
Windows containers cannot be domain joined. However, they can still use Active Directory domain identities to support various authentication scenarios.
This is achieved by configuring the Windows container to run with a Group Managed Service Account (gMSA).
When this container is run, the underlying Container host retrieves the gMSA password from AD and hands it over to the Container in order to authenticate into network resources. General information on how to create GMSA for Windows containers can be found in https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts.

The following are the steps to configure your IIS container to support Windows authentication

# One-time setup in Active Directory Server - Generate the KDS Root Key which will be needed for gMSA password rotation.
```
Add-KdsRootKey -EffectiveImmediately
```

# Creating GMSA and granting access to Container hosts
The recommended way of setting this up is to execute the two provided powershell scripts on the Container host in the following order (on the Container host):
## DomainJoinAddToSecGroup.ps1 - This can create a new AD Security Group, Domain Join the Container Host and add it to this Security Group. Note that this script will likely need a reboot. Usage example:
```
DomainJoinAddToSecGroup.ps1 -ADDomainName CompanyDomain.com -ADDNSIp 10.0.0.1 -ADSecurityGroup myIISContainerHosts -CreateADSecurityGroup:$true
```

## CreateCredSpecFile.ps1 - This can create a new GMSA, grant access to the AD Security Group (created above) and then create a Credential Spec file inside the host that will be injected into the Container during the docker run command to make the authentication work. Usage example:
```
CreateCredSpecFile.ps1 -GMSAName MyGMSAForIIS -CreateGMSA:$true -ADSecurityGroup myIISContainerHosts
```

# Authorizing this GMSA on backend Servers
If IIS Server (now running in Container) needs to authenticate/authorize into a backend SQL Server, then the GMSA needs to be added to the SQL Server instance's Security Login User accounts and under the Database's User accounts.

# Notes about Creating AD Security Group and GMSA
## Create AD Security Group
The recommended permission model for GMSA is that we create an AD Security Group and grant GMSA access to this group. Each container host is added to this Security group. In case you do not want to use the script to create this, you can manually do so by executing the "New-AdGroup" cmdlet inside the Active Directory Server.

## Creating GMSA
GMSA is typically setup per IIS Application or Site. In case you do not want to use the script to create this, you can manually do so by executing the "New-ADServiceAccount" cmdlet inside the Active Directory Server.
