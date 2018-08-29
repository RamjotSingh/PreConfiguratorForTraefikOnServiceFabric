# Pre-Configurator For Traefik On Service Fabric
Allows per environment configuration of Traefik on Service Fabric

## Traefik On Service Fabric
Refer to [this](https://github.com/jjcollinge/traefik-on-service-fabric) repo for the Service Fabric integration for Traefik. Ensure you complete the setups there (like downloading the Traefik binary and placing it in correct directory) before you continue.

## Windows Integrations
Traefik Pre-Configurator allows you configure and change parts of Traefik configuration without changing the toml file or maintaining  multiple packages for different environments.
This is done by utilizing [Service fabric per environment configuration](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-manage-multiple-environment-app-configuration)

## How to?
Refer to Samples directory for a working sample of how the integration works.

### Integrating pre-configurator in an existing Traefik Solution
Integration of pre-configurator involves 3 steps:-
1. Copy the binaries required for Pre-Configuration to run
2. Enable pre-configurator to run using [SetupEntryPoint](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-run-script-at-service-startup)
3. Configure per-environment Traefik settings using Application Parameter

#### Copying binaries before Traefik packaging
You can compile once and copy next to Traefik binary or you can do this using build process. Do perform copy on every build follow the sample project.
In sample project, the Traefik.sfproj has a PreBuildEvent. This PreBuildEvent copies the required binaries.
```
  <PropertyGroup>
    <PreBuildEvent>xcopy /I /Y $(MSBuildThisFileDirectory)..\..\Src\TraefikPreConfiguratorWindows\bin\$(Configuration) $(MSBuildThisFileDirectory)ApplicationPackageRoot\TraefikPkg\Code</PreBuildEvent>
  </PropertyGroup>
```
Adjust the path to copy to the correct directory. This requires the binaries to be compiled before they can be copied.
To ensure that the binaries are always present before copy you can add a condition to the Validate MS Build target as shown below (just the last line is required, rest are just for completeness)
```
  <Target Name="ValidateMSBuildFiles">
    <Error Condition="!Exists('..\packages\Microsoft.VisualStudio.Azure.Fabric.MSBuild.1.6.6\build\Microsoft.VisualStudio.Azure.Fabric.Application.props')" Text="Unable to find the '..\packages\Microsoft.VisualStudio.Azure.Fabric.MSBuild.1.6.6\build\Microsoft.VisualStudio.Azure.Fabric.Application.props' file. Please restore the 'Microsoft.VisualStudio.Azure.Fabric.MSBuild' Nuget package." />
    <Error Condition="!Exists('..\packages\Microsoft.VisualStudio.Azure.Fabric.MSBuild.1.6.6\build\Microsoft.VisualStudio.Azure.Fabric.Application.targets')" Text="Unable to find the '..\packages\Microsoft.VisualStudio.Azure.Fabric.MSBuild.1.6.6\build\Microsoft.VisualStudio.Azure.Fabric.Application.targets' file. Please restore the 'Microsoft.VisualStudio.Azure.Fabric.MSBuild' Nuget package." />
    <Error Condition="!Exists('$(MSBuildThisFileDirectory)..\..\Src\TraefikPreConfiguratorWindows\bin\$(Configuration)\TraefikPreConfiguratorWindows.exe')" Text="Unable to find the Pre-Configurator binaries. Please compile the Pre-Configurator before compiling this Traefik project" />
  </Target>
```
You can also setup the pre-configurator as a project dependency to Traefik project. This will ensure that pre-configurator project is always compiled before Traefik project.
To do this
1. Right click the solution and select Project Dependencies
2. Select the Traefik project
3. Select pre-Configurator project as a dependency.

This requires the pre-configurator project to be present in same solution.

#### Setup pre-configurator to run before the Traefik
This can be setup in the Traefik service manifest. Refer to [Sample Service Manifest](/Samples/Traefik/ApplicationPackageRoot/TraefikPkg/ServiceManifest.xml)
```
    <SetupEntryPoint>
      <ExeHost>
        <Program>TraefikPreConfiguratorWindows.exe</Program>
        <Arguments>-UseEnv</Arguments>
        <WorkingFolder>CodePackage</WorkingFolder>
         <!--Uncomment to log console output (both stdout and stderr) to one of the
             service's working directories. Do not use in production.--> 
        <!--<ConsoleRedirection FileRetentionCount="5" FileMaxSizeInKb="20480" />-->
      </ExeHost>
    </SetupEntryPoint>
```
This will ensure that pre-configurator is run before the Traefik binary.

To provide the required configuration to pre-configurator, also add the following environment variables to Service manifest
```
    <EnvironmentVariables>
      <EnvironmentVariable Name="ConfigureCerts" Value=""/>
      <EnvironmentVariable Name="ApplicationInsightsKey" Value=""/>
      <EnvironmentVariable Name="CertsToConfigure" Value=""/>
      <EnvironmentVariable Name="KeyVaultUri" Value=""/>
      <EnvironmentVariable Name="KeyVaultClientId" Value=""/>
      <EnvironmentVariable Name="KeyVaultClientSecret" Value="" />
      <EnvironmentVariable Name="KeyVaultClientCert" Value=""/>
    </EnvironmentVariables>
```

To provide values for each environment, these also need to be declared in the Application Manifest. Refer to [Sample Application Manifest](/Samples/Traefik/ApplicationPackageRoot/ApplicationManifest.xml)

```
    <!-- Parameters for Traefik PreConfigurator. These can now be overriden in any Application Parameter to cater to specific cluster's needs. -->
    <Parameter Name="TraefikApplicationInsightsKey" DefaultValue=""/>
    <Parameter Name="TraefikCertsToConfigure" DefaultValue=""/>
    <Parameter Name="TraefikKeyVaultUri" DefaultValue=""/>
    <Parameter Name="TraefikKeyVaultClientId" DefaultValue=""/>
    <Parameter Name="TraefikKeyVaultClientSecret" DefaultValue=""/>
    <Parameter Name="TraefikKeyVaultClientCert" DefaultValue=""/>
```

and override the parameters for the Traefik service

```
  <ServiceManifestImport>
    <ServiceManifestRef ServiceManifestName="TraefikPkg" ServiceManifestVersion="1.0.0" />
    <ConfigOverrides />
    <!-- Environment Overrides to allow overriding value for different environments -->
    <EnvironmentOverrides CodePackageRef="Code">
      <EnvironmentVariable Name="ApplicationInsightsKey" Value="[TraefikApplicationInsightsKey]"/>
      <EnvironmentVariable Name="CertsToConfigure" Value="[TraefikCertsToConfigure]"/>
      <EnvironmentVariable Name="KeyVaultUri" Value="[TraefikKeyVaultUri]"/>
      <EnvironmentVariable Name="KeyVaultClientId" Value="[TraefikKeyVaultClientId]"/>
      <EnvironmentVariable Name="KeyVaultClientSecret" Value="[TraefikKeyVaultClientSecret]"/>
      <EnvironmentVariable Name="KeyVaultClientCert" Value="[TraefikKeyVaultClientCert]"/>
    </EnvironmentOverrides>
    <Policies>
      <RunAsPolicy CodePackageRef="Code" UserRef="AdminUser" EntryPointType="All" />
    </Policies>
  </ServiceManifestImport>
```
#### Configure per-environment parameters
Once the Application Manifest is set to provide values to Traefik service based on the values provided to it, now we can use Application Parameters to override values for different environment.
Refer to the [Sample Application Parameters](/Samples/Traefik/ApplicationParameters/Cloud.xml) to see how to configure values
```
<Application Name="fabric:/Traefik" xmlns="http://schemas.microsoft.com/2011/01/fabric" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Parameters>
    <Parameter Name="TraefikApplicationInsightsKey" Value="Application insights key"/>
    <Parameter Name="TraefikCertsToConfigure" Value="sslcert;KeyVault;SSLCert,clustercert;LocalMachine;0efeb8fa621a4a0be2378f2b60eb2142ce846663"/>
    <Parameter Name="TraefikKeyVaultUri" Value="https://mysamplekeyvault.vault.azure.net/"/>
    <Parameter Name="TraefikKeyVaultClientId" Value="591073d7-7f30-4472-b856-e4ceccf9f764"/>
    <Parameter Name="TraefikKeyVaultClientSecret" Value=""/>
    <Parameter Name="TraefikKeyVaultClientCert" Value="7745662161272a590cf1d160e8777b03be3cca14"/>
  </Parameters>
</Application>
```
The parameters are as follows
- **TraefikApplicationInsightsKey** - Application insights key. This is where the pre-configurator will send logs to
- **TraefikCertsToConfigure** - Certificates to configure. These are to be specified in *FileName*;*Source*;*Identifier* format with individual certs comma separated

     FileName is the filename of the cert on disk

     Source can be LocalMachine or KeyVault, depending on which the certificate will either be picked from LocalMachine\MY store or the configured KeyVault

     Identifier is Certificate thumbprint for LocalMachine and KeyVault secret name for KeyVault.

*Note the certificates MUST be uploaded to keyvault using the Certificates option and not Secrets*
- **TraefikKeyVaultUri** - Only required if you want to use KeyVault. This should be the KeyVault Uri. Start with https://
- **TraefikKeyVaultClientId** - Only required if using KeyVault. An Application must be associated with KeyVault to access it. Refer [this](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-use-from-web-application#authenticate-with-a-certificate-instead-of-a-client-secret) to setup
- **TraefikKeyVaultClientSecret** or **TraefikKeyVaultClientCert** - Only required if using KeyVault. Depending on what option you used in the keyvault application setup, you need to specify the client secret or certificate thumbprint for the application certificate. If the certificate is used, it must be installed on the machine. TraefikKeyVaultClientCert is the preferred option as it ensures no secrets are present in the configuration files.

Deploy the Traefik service fabric application and pre-configurator should configure the Traefik instance before running.

## Appendix 1 - Using HTTPS on Traefik
The above process allows you to dump SSL certs onto the machine for Traefik to use. Refer to [sample toml file](/Samples/Traefik/ApplicationPackageRoot/TraefikPkg/Code/traefik.toml) on how to specify these. These allows Traefik to bind to 443 port.
However you need to also change the ServiceManifest to allow binding to port 443. Refer to the [sample manifest file](/Samples/Traefik/ApplicationPackageRoot/TraefikPkg/ServiceManifest.xml) and Endpoints section on how to do the same. You can optionally enable port 80 as well if needed.
```
defaultEntryPoints = ["https"]
insecureSkipVerify = true

# Entrypoints definition
#
# Optional
# Default:
[entryPoints]
#[entryPoints.http]
#address = ":80"
[entryPoints.traefik]
address = ":8080"
# Enable Https. Refer to https://docs.traefik.io/configuration/entrypoints/#tls for examples
[entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
      [[entryPoints.https.tls.certificates]]
      certFile = "certs/sslcert.crt"
      keyFile = "certs/sslcert.key"
```

## Appendix 2 - Searching for certs by SubjectName and other methods
Often at times it can be tricky to keep using thumbprint for certificates as it will require changes to Traefik configuration everytime the certificates are rotated (renewed etc.). For such cases it is usually better to use other
identifiers like Subject name. 

Pre-Configurator supports this by adding [X509FindType](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509findtype) value at the end of the certificate identifier separated by ':'. For example to search by Subject name you can use

```clustercert;LocalMachine;MyClusterCert:FindBySubjectName``` 

where MyClusterCert is the Subject name of the certificate. Similarily you can use 

```clustercert;LocalMachine;0efeb8fa621a4a0be2378f2b60eb2142ce846663:FindByThumbprint``` 

although it will have the same result as 

```clustercert;LocalMachine;0efeb8fa621a4a0be2378f2b60eb2142ce846663```. 

This method is only supported for Local Machine certificates and not for KeyVault certificates.
