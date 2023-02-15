//! The Security WMI Providers allow applications to interact with the Trusted Platform Module (TPM)
//! and BitLocker Drive Encryption (BDE) through the unified management framework of Windows
//! Management Instrumentation (WMI).
//!
//! Example:
//! ```rust
//! use wmi_security::COMLibrary;
//! use wmi_security::{get_encryption_volume_state, get_tpm_state};
//!
//! fn main() {
//!     let com_con = COMLibrary::new().unwrap();
//!
//!     println!(
//!         "{:#?}\n{:#?}",
//!         get_tpm_state(com_con),
//!         get_encryption_volume_state(com_con)
//!     );
//! }
//! ```

use serde::Deserialize;
use wmi::WMIConnection;

pub use wmi::COMLibrary;

/// The Win32_Tpm class represents the Trusted Platform Module (TPM), a hardware security chip
/// that provides a root of trust for a computer system.
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Tpm")]
#[serde(rename_all = "PascalCase")]
pub struct Win32Tpm {
    /// Indicates whether the TPM is activated.
    ///
    /// true if the device is activated (that is, if IsActivated_InitialValue is true); otherwise,
    /// false.
    ///
    /// This value is stored when the class is instantiated. It is possible for the TPM to change
    /// state between the instantiation and when you check this value. To check whether the TPM is
    /// activated in real time, use the IsActivated method.
    ///
    /// Windows Server 2008 and Windows Vista: This property is not available.
    #[serde(rename = "IsActivated_InitialValue")]
    pub is_activated_initial_value: Option<bool>,
    /// Indicates whether the TPM is enabled.
    ///
    /// true if the device is enabled (that is, if IsEnabled_InitialValue is true); otherwise,
    /// false.
    ///
    /// This value is stored when the class is instantiated. It is possible for the TPM to change
    /// state between the instantiation and when you check this value. To check whether the TPM is
    /// enabled in real time, use the IsEnabled method.
    ///
    /// Windows Server 2008 and Windows Vista: This property is not available.
    #[serde(rename = "IsEnabled_InitialValue")]
    pub is_enabled_initial_value: Option<bool>,
    /// Indicates whether the TPM has an owner.
    ///
    /// true if the device has an owner (that is, if IsOwned_InitialValue is true); otherwise,
    /// false.
    ///
    /// This value is stored when the class is instantiated. It is possible for the TPM to change
    /// state between the instantiation and when you check this value. To check whether the TPM is
    /// owned in real time, use the IsOwned method.
    ///
    /// Windows Server 2008 and Windows Vista: This property is not available.
    #[serde(rename = "IsOwned_InitialValue")]
    pub is_owned_initial_value: Option<bool>,
    /// The version of the Trusted Computing Group (TCG) specification that the TPM supports. This
    /// value includes the major and minor TCG specification version, the specification revision
    /// level, and the errata revision level. All values are in hexadecimal. For example, a version
    /// information of "1.2, 2, 0" indicates that the device was implemented to TCG specification
    /// version 1.2, revision level 2, and with no errata.
    ///
    /// When the data is unavailable, "Not Supported" is returned.
    pub spec_version: Option<String>,
    /// The version of the TPM, as specified by the manufacturer.
    ///
    /// When the data is unavailable, "Not Supported" is returned.
    pub manufacturer_version: Option<String>,
    /// Other manufacturer-specific version information for the TPM.
    ///
    /// When the data is unavailable, "Not Supported" is returned.
    pub manufacturer_version_info: Option<String>,
    /// The identifying information that uniquely names the TPM manufacturer.
    ///
    /// When the data is unavailable, zero is returned.
    ///
    /// This integer value can be translated to a string value by interpreting each byte as an ASCII
    /// character. For example, an integer value of 1414548736 can be divided into these 4 bytes:
    /// 0x54, 0x50, 0x4D, and 0x00. Assuming the string is interpreted from left to right, this
    /// integer value translated to a string value of "TPM".
    pub manufacturer_id: Option<u32>,
    /// The version of the Physical Presence Interface, a communication mechanism used to run device
    /// operations that require physical presence, that the computer supports.
    ///
    /// This interface must be available to run TPM physical presence operations. The Win32_Tpm
    /// methods SetPhysicalPresenceRequest, GetPhysicalPresenceRequest,
    /// GetPhysicalPresenceTransition, and GetPhysicalPresenceResponse expose the capabilities of
    /// the Physical Presence Interface.
    ///
    /// When the data is unavailable, "Not Supported" is returned.
    pub physical_presence_version_info: Option<String>,
}

/// The Win32_EncryptableVolume WMI provider class represents an area of storage on a hard disk that
/// can be protected by using BitLocker Drive Encryption. Only NTFS volumes can be encrypted. It can
/// be a volume that contains an operating system, or it can be a data volume on the local disk. It
/// cannot be a network drive.
///
/// To realize the benefits of BitLocker, you must specify a protection method for the volume's
/// encryption key and then fully encrypt the volume.
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
pub struct Win32EncryptableVolume {
    /// A unique identifier for the volume on this system. Use this to associate a volume with other
    /// WMI provider classes, for example, Win32_Volume.
    #[serde(rename = "DeviceID")]
    pub device_id: Option<String>,
    /// A persistent identifier for the volume on this system. This identifier is exclusive to
    /// Win32_EncryptableVolume.
    ///
    /// This identifier is an empty string if the volume is a standard fully decrypted NTFS volume;
    /// otherwise, it has a unique value.
    #[serde(rename = "PersistentVolumeID")]
    pub persistent_volume_id: Option<String>,
    /// The drive letter of the volume. This identifier can be used to associate a volume with other
    /// WMI provider classes, for example Win32_Volume.
    ///
    /// For volumes without drive letters, this value is NULL.
    pub drive_letter: Option<String>,
    /// The status of the volume, whether or not BitLocker is protecting the volume. This value is
    /// stored when the class is instantiated. It is possible for the protection status to change
    /// state between instantiation and when you check the value. To check the value of the
    /// ProtectionStatus property in real time, use the GetProtectionStatus method.
    ///
    /// | Value | Meaning                                                                                                                                                     |
    /// |-------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
    /// | 0     | PROTECTION OFF  The volume is not encrypted, partially encrypted, or the volume's encryption key for the volume is available in the clear on the hard disk. |
    /// | 1     | PROTECTION ON  The volume is fully encrypted and the encryption key for the volume is not available in the clear on the hard disk.                          |
    /// | 2     | PROTECTION UNKNOWN  The volume protection status cannot be determined. One potential cause is that the volume is in a locked state.                         |
    pub protection_status: Option<u32>,
}

pub fn get_tpm_state(com_con: COMLibrary) -> Result<Vec<Win32Tpm>, Box<dyn std::error::Error>> {
    let wmi_con =
        WMIConnection::with_namespace_path("root\\CIMV2\\Security\\MicrosoftTpm", com_con)?;
    let results: Vec<Win32Tpm> = wmi_con.query()?;

    Ok(results)
}

pub fn get_encryption_volume_state(
    com_con: COMLibrary,
) -> Result<Vec<Win32EncryptableVolume>, Box<dyn std::error::Error>> {
    let wmi_con = WMIConnection::with_namespace_path(
        "Root\\CIMV2\\Security\\MicrosoftVolumeEncryption",
        com_con,
    )
    .unwrap();
    let results: Vec<Win32EncryptableVolume> = wmi_con.query().unwrap();

    Ok(results)
}
