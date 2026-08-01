@description('Azure region selected by the administrator-owned execution class.')
param location string
param vmName string
param nicName string
param nsgName string
param diskName string
param subnetResourceId string
param imageVersionResourceId string
param vmSize string
param diskSizeGiB int
param diskStorageAccountType string
param sshPublicKey string
param bootstrapSSHEnabled bool
param mediated bool
param driverSourceCIDR string
param dnsServer string
param outboundRules array
param tags object
param adminUsername string

var nvtOutboundRules = [for (rule, index) in outboundRules: {
  name: 'allow-nvt-${index}'
  properties: {
    protocol: 'Tcp'
    sourcePortRange: '*'
    destinationPortRange: string(rule.port)
    sourceAddressPrefix: '*'
    destinationAddressPrefix: rule.address
    access: 'Allow'
    priority: 200 + index
    direction: 'Outbound'
  }
}]

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: concat(
      bootstrapSSHEnabled ? [
        {
          name: 'allow-bootstrap-ssh'
          properties: {
            protocol: 'Tcp'
            sourcePortRange: '*'
            destinationPortRange: '22'
            sourceAddressPrefix: driverSourceCIDR
            destinationAddressPrefix: '*'
            access: 'Allow'
            priority: 100
            direction: 'Inbound'
          }
        }
      ] : [],
      [
        {
          name: 'deny-all-inbound'
          properties: {
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: '*'
            access: 'Deny'
            priority: 4095
            direction: 'Inbound'
          }
        }
      ],
      mediated ? concat(nvtOutboundRules, [
        {
          name: 'allow-dns-tcp'
          properties: {
            protocol: 'Tcp'
            sourcePortRange: '*'
            destinationPortRange: '53'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: dnsServer
            access: 'Allow'
            priority: 500
            direction: 'Outbound'
          }
        }
        {
          name: 'allow-dns-udp'
          properties: {
            protocol: 'Udp'
            sourcePortRange: '*'
            destinationPortRange: '53'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: dnsServer
            access: 'Allow'
            priority: 501
            direction: 'Outbound'
          }
        }
        {
          name: 'deny-azure-platform-imds'
          properties: {
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: 'AzurePlatformIMDS'
            access: 'Deny'
            priority: 600
            direction: 'Outbound'
          }
        }
        {
          name: 'deny-azure-platform-lkm'
          properties: {
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: 'AzurePlatformLKM'
            access: 'Deny'
            priority: 601
            direction: 'Outbound'
          }
        }
        {
          name: 'deny-azure-platform-dns'
          properties: {
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: 'AzurePlatformDNS'
            access: 'Deny'
            priority: 602
            direction: 'Outbound'
          }
        }
        {
          name: 'deny-all-outbound'
          properties: {
            protocol: '*'
            sourcePortRange: '*'
            destinationPortRange: '*'
            sourceAddressPrefix: '*'
            destinationAddressPrefix: '*'
            access: 'Deny'
            priority: 4096
            direction: 'Outbound'
          }
        }
      ]) : []
    )
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    enableAcceleratedNetworking: false
    enableIPForwarding: false
    dnsSettings: {
      dnsServers: [dnsServer]
    }
    networkSecurityGroup: {
      id: nsg.id
    }
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          primary: true
          subnet: {
            id: subnetResourceId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  tags: tags
  identity: {
    type: 'None'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      allowExtensionOperations: false
      requireGuestProvisionSignal: false
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: false
        ssh: {
          publicKeys: bootstrapSSHEnabled ? [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ] : []
        }
      }
    }
    storageProfile: {
      imageReference: {
        id: imageVersionResourceId
      }
      osDisk: {
        name: diskName
        createOption: 'FromImage'
        deleteOption: 'Detach'
        diskSizeGB: diskSizeGiB
        managedDisk: {
          storageAccountType: diskStorageAccountType
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Detach'
            primary: true
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
  }
}

// A generalized gallery image must be selected by the VM with FromImage while
// osProfile is present. The VM creates the deterministically named managed OS
// disk; this dependent resource then applies the owned tags and disables disk
// export without changing the immutable creation source.
resource osDisk 'Microsoft.Compute/disks@2024-03-02' = {
  name: diskName
  location: location
  tags: tags
  sku: {
    name: diskStorageAccountType
  }
  properties: {
    osType: 'Linux'
    diskSizeGB: diskSizeGiB
    networkAccessPolicy: 'DenyAll'
    publicNetworkAccess: 'Disabled'
    creationData: {
      createOption: 'FromImage'
      imageReference: {
        id: imageVersionResourceId
      }
    }
  }
  dependsOn: [
    vm
  ]
}
