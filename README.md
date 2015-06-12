**Update** 2015-06-12 - Edited to work with CakePHP version 2.6.x.

Although there have been other Mcrypt libraries created for CakePHP, I haven't seen any of them with nearly as many features as this one. Many of them are Components, used in the controller. That goes against the Fat Model, Skinny Controller philosophy.

This behavior was based off of core CakePHP behaviors in how it functions. It will hopefully be much more capable due to this design decision.

INCOMPLETE:
- Cannot yet be called directly from within a controller (or model) by using $this->Model->encrypt()
- Not compatible with Containable when referring to encrypted fields in a related model
- Is not currently able to automatically decrypt fields from an encrypted model (A) from another model (B)
    // Example: ModelA.Field1 (encrypted)
             $this->ModelB->find('all');	//assuming ModelA is related to ModelB and are joined in this query
             // ... Field1 will still be encrypted.

Therefore, in its current form, this behavior works best on models whose fields can easily stand alone without being needed in other models' queries. However, that's why Github's so awesome. Share, fix, expand, share again.

USAGE:
Add the behavior to your model's $actsAs property. In the following example, the fields `username` and `barcode` will automatically be encrypted/decrypted on the fly. No further interaction is required on your part.

    var $actsAs = array('Mcrypt' =>
        array(
            'fields' => array('username','barcode')
        )
    );

All available properties (and their descriptions) for initialization with the Mcrypt behavior:
 
| Variable | Description |
| --- | --- |
| **method**: | The Mcrypt cipher to use. Defaults to MCRYPT_CAST_128 For possible values see: http://php.net/manual/mcrypt.ciphers.php |
| **mode**: | Some cipher methods have multiple algorith modes to choose from. By default the Mcrypt library will default to null, because a cipher has been set as default in this library that has multiple modes, this library defaults to MCRYPT_MODE_ECB. To determine what modes are available on your system please see: http://php.net/mcrypt_list_modes |
| **iv**: | "Initialization Vector", used for encryption and decryption. This value must not be changed once values are encrypted, or they will not be decrypted properly.  This will not be used in all types of encryption, but can still be set. Defaults to an abstracted value of the Security.salt in the CakePHP core. |
| **key**: | "Symmetric Key", also used in encryption. This must also not be changed once values are encrypted.  Defaults to an abstracted valueof the Security.salt in the CakePHP core. |
| **fields**: | An array of string values representing the Model's field names to be handled with the automatic encryption/decryption of this behavior. |
| **prefix**: | A value prepended to the beginning of an encrypted value's string to assist in the identification of currently encrypted values. Defaults to the string '$E$'. |
| **autoDecrypt**: | Whether or not to automatically decrypt the fields or not. Decryption can sometimes be resource intensive on miltidimensional find results. You may disable the automatic decryption to prevent this, and then call the behavior's public decrypt() method manually where necessary. Defaults to true. |
| **algorithmDirectory**: | The location of your system's mcrypt libraries for your chosen cipher method. This typically does not need to be set, and will default to null, using the system default instead. |
| **modeDirectory**: | The location, or file path, of your system's cipher modes, also typically does not need to be set, and will default to null, thereby using the system's defaults instead. |
| **disabledTypes**: | An array of CakePHP-specific datatypes that should be ignored in the encryption process.  For instance, a boolean value (either 1, or 0) would typically have a length of 8 characters after encryption (plus the  prefix). This would not store back in to the database. As such, boolean values are hard-coded as disabled. This defaults to the following array: `array('boolean', 'integer', 'float', 'datetime', 'timestamp', 'time', 'date', 'primary_key');` Typically, only varchar, blob, and text fields should be used here, but customization is allowed for unforeseen requirements. |
