<?php

class McryptBehavior extends ModelBehavior
{
	//////////////////////////////////////////////////////////////////
	/// NOTE: From the PHP Manual:                                 ///
	///		  If you are for example storing the data in a MySQL   ///
	///		  database remember that varchar fields automatically  ///
	///		  have trailing spaces removed during insertion. As    ///
	///		  encrypted data can end in a space (ASCII 32), the    ///
	///		  data will be damaged by this removal. Store data in  ///
	///		  a tinyblob/tinytext (or larger) field instead.       ///
	//////////////////////////////////////////////////////////////////
	/**
	 * it is suggested, for the protection of data, that any fields stored to a
	 * database in an encrypted form be saved in a field that does not trim null
	 * characters to save space, as the null characters may be necessary in the
	 * encryption and decryption process under certain situations
	 */

	/**
	 * Default configuration for this behavior
	 *
	 * @var array
	 * @access public
	 */
	var $defaultConfig = array(
		'method' => MCRYPT_CAST_128,
		'mode' => MCRYPT_MODE_ECB,
		'prefix' => '$E$',
		'autoDecrypt' => true,
		'algorithmDirectory' => '',
		'modeDirectory' => '',
		'disabledTypes' => array('boolean', 'integer', 'float', 'datetime', 'timestamp', 'time', 'date', 'primary_key')
	);

	/**
	 * Holds the configuration data for the behavior during runtime.
	 *
	 * @var array
	 * @access private
	 */
	var $config = array();

	/**
	 * Stores the current model's name/alias so that the reference variable does not
	 * have to be passed to a majority of the class methods.
	 *
	 * @var string
	 * @access private
	 */
	var $modelName;		//useful for non-parent class methods

	/**
	 * The cipher resource, used for the PHP encryption and decryption functions.
	 *
	 * @var resource
	 * @access private
	 */
	var $resource;		//stores mcrypt resource object

/**
 * Initiate behavior for the model using specified settings. Available settings:
 *
 * iv: 			"Initialization Vector", used for encryption and decryption. This
 * 				value must not be changed once values are encrypted, or they will
 * 				not be decrypted properly.  This will not be used in all types of
 * 				encryption, but can still be set.  Defaults to an abstracted value
 * 				of the Security.salt in the CakePHP core.
 *
 * key:			"Symmetric Key", also used in encryption.  This must also not be
 * 				changed once values are encrypted.  Defaults to an abstracted value
 * 				of the Security.salt in the CakePHP core.
 *
 * fields:		An array of string values representing the Model's field names to be
 * 				handled with the automatic encryption/decryption of this behavior.
 *
 * prefix:		A value prepended to the beginning of an encrypted value's string to
 * 				assist in the identification of currently encrypted values. Defaults
 * 				to the string '$E$'.
 *
 * autoDecrypt: Whether or not to automatically decrypt the fields or not. Decryption
 * 				can sometimes be resource intensive on miltidimensional find results.
 * 				You may disable the automatic decryption to prevent this, and then
 * 				call the behavior's public decrypt() method manually where necessary.
 *
 * algorithmDirectory:	The location of your system's mcrypt libraries for your chosen
 * 				cipher method. This typically does not need to be set, and will default
 * 				to null, using the system default instead.
 *
 * modeDirectory:	The location, or file path, of your system's cipher modes, also
 * 				typically does not need to be set, and will default to null, thereby
 * 				using the system's defaults instead.
 *
 * disabledTypes:	An array of CakePHP-specific datatypes that should be ignored in
 * 				the encryption process.  For instance, a boolean value (either 1, or 0)
 * 				would typically have a length of 8 characters after encryption (plus the
 * 				prefix). This would not store back in to the database.  As such, boolean
 * 				values are hard-coded as disabled. This defaults to the following array:
 *				array('boolean', 'integer', 'float', 'datetime', 'timestamp', 'time',
 *						'date', 'primary_key');
 *				Typically, only varchar, blob, and text fields should be used here, but
 *				customization is allowed for unforeseen requirements.
 *
 * @param object $Model Model using the behavior
 * @param array $settings Settings to override for model.
 * @access public
 */
	public function setup(Model $Model, $settings = array()){
		$this->modelName = $Model->alias;
		if(!isset($this->config[$Model->alias])){
			$this->config[$Model->alias] = $this->defaultConfig;
		}
		//apply all user-specified criteria to our configuration
		$this->config[$Model->alias] = array_merge($this->config[$Model->alias], (array)$settings);

		//trigger an error if the chosen cipher method doesn't work on the current system
		if(!in_array($this->config[$Model->alias]['method'], mcrypt_list_algorithms())){
			trigger_error('The chosen cipher method, '.(string)$this->config[$Model->alias]['method'].', is not supported on this system.', E_USER_ERROR);
		}

		//set any remaining properties if not yet defined
		$this->resource = mcrypt_module_open($this->config[$Model->alias]['method'], $this->config[$Model->alias]['algorithmDirectory'], $this->config[$Model->alias]['mode'], $this->config[$Model->alias]['modeDirectory']);
		if(!$this->resource){
			trigger_error('Unable to open the chosen cipher method. Verify your MCrypt library exists and the paths are correct.', E_USER_ERROR);
		}
		if(!isset($settings['iv'])){
			$this->config[$Model->alias]['iv'] = $this->_setIV(Configure::read('Security.salt'));
		}
		if(!isset($settings['key'])){
			$this->config[$Model->alias]['key'] = $this->_setKey(Configure::read('Security.salt'));
		}
	}

	/**
	 * Sets the Initialization Vector for the encryption/decryption process.
	 *
	 * @return string
	 * @param object $string
	 * @access protected
	 */
	protected function _setIV($string)
	{
		$iv_size = mcrypt_enc_get_iv_size($this->resource);
		if($iv_size !== 0){
			if(strlen($string) > $iv_size){
				$string = substr($string, 0, $iv_size);
			}else if(strlen($string) < $iv_size){
				$string = str_pad($string, $iv_size, $string, STR_PAD_RIGHT);
			}
			return $string;
		}else{
			//the IV is ignored in the chosen algorithm
			return null;
		}
	}

	/**
	 * Sets the symmetrical key for the encryption/decryption process.
	 *
	 * @return string
	 * @param object $string
	 * @access protected
	 */
	protected function _setKey($string)
	{
		$key_size = mcrypt_enc_get_key_size($this->resource);
		if($key_size < strlen($string)){
			$string = substr($string, 0, $key_size);
		}
		return strrev($string);
	}

	/**
	 * Runs before a find() operation. Used to automatically encrypt any specified
	 * fields to enable proper matching in the database.
	 *
	 * @param object $Model	Model using the behavior
	 * @param array $query Query parameters as set by cake
	 * @return array
	 * @access public
	 */
	public function beforeFind(Model $Model, $query)
	{
		if(!empty($query['conditions']) && !empty($this->config[$Model->alias]['fields'])){
			$query['conditions'] = $this->_setConditions($Model, $query['conditions']);
		}
		return $query;
	}

	/**
	 * A helper method to handle the grunt work of the beforeFind method.  This
	 * attempts to encrypt values of fields that are supposed to be encrypted
	 * in the database for properly structured find calls.
	 *
	 * @return array
	 * @param object $Model Model using the behavior
	 * @param object $conditions The conditions array in the find call that may
	 * 				 			 contain values to encrypt.
	 * @access private
	 */
	private function _setConditions($Model, $conditions){
		if(!is_array($this->config[$Model->alias]['fields'])){
			$this->config[$Model->alias]['fields'] = array($this->config[$Model->alias]['fields']);
		}
		if(!is_array($this->config[$Model->alias]['disabledTypes'])){
			$this->config[$Model->alias]['disabledTypes'] = array($this->config[$Model->alias]['disabledTypes']);
		}
		if(is_array($conditions)){
			foreach($conditions as $key => $value){
				if(strpos($key, '.') !== false){
					$fieldName = substr($key, strpos($key, '.')+1, strlen($key));
				}else{
					$fieldName = $key;
				}
				if(is_array($value)){
					//check to make sure $key != fieldname
					if(in_array($fieldName, $this->config[$Model->alias]['fields'])){
						foreach($value as $subkey => $subvalue){
							$datatype = $Model->_schema[$fieldName]['type'];
							if(!in_array($datatype, $this->config[$Model->alias]['disabledTypes'])
							&& !$this->isEncrypted($subvalue)
							&& @strlen($subvalue) > 0){
								$conditions[$key][$subkey] = $this->_encryptField($subvalue, $datatype);
							}
						}
					}else{
						$conditions[$key] = $this->_setConditions($Model, $value);
					}
				}else{
					//match field? ...get schema type...
					//be wary of field comparison instead of value comparison
					if(in_array($fieldName, $this->config[$Model->alias]['fields'], true)){
						$datatype = $Model->_schema[$fieldName]['type'];
						if(!in_array($datatype, $this->config[$Model->alias]['disabledTypes'])
						&& !$this->isEncrypted($value)
						&& strlen($value) > 0){
							$conditions[$key] = $this->_encryptField($value, $datatype);
						}
					}else if(strpos($value, ' ') !== false){
						//Possible array structure (that work w/encrypted data) at this point:
						//[0] => "User.username = 'string'"
						//[0] => 'User.username = "string"'
						//[0] => "User.username = `Table`.`field`"
						//[0] => "User.username = Table.field"
						//[0] => "User.username != Table.field"
						//[0] => "User.username <> Table.field"
						if(strpos($value, '"') || strpos($value, '\'')){
							//need to modify the value here, if key is found in value
							//we can only match against equivalents when dealing with encrypted data
							$pattern = '/(?:'.$Model->alias.'\.)?(\w+) (?:=|!=|<>) (\'|\")(.+)[^\\\\]\2/i';
							$matches = null;
							preg_match($pattern, $value, $matches);
							//matches[0] = whole string...matches[1] = fieldName...matches[2] = quote style...matches[3] = value
							if(!empty($matches) && in_array($matches[1], $this->config[$Model->alias]['fields'], true)){
								$datatype = $Model->_schema[$matches[1]]['type'];
								if(!in_array($datatype, $this->config[$Model->alias]['disabledTypes'])
								&& !$this->isEncrypted($matches[3])
								&& strlen($matches[3] > 0)){
									$conditions[$key] = str_replace($matches[3], $this->_encryptField($matches[3], $datatype), $value);
								}
							}
						}
					}
				}
			}
		}
		return $conditions;
	}

	/**
	 * After save callback; encrypts any fields set for auto-encryption (if not
	 * already encrypted) within the model prior to save.
	 *
	 * @return boolean
	 * @param object $Model Model using the behavior
	 * @access public
	 */
	public function beforeSave(Model $Model, $options = array()){
		if(isset($this->config[$Model->alias]['fields'])){
			//convert singular values to array
			//we do this here in case of on-the-fly settings changes in model/controller
			$fields_to_encrypt = array();
			if(!empty($this->config[$Model->alias]['fields'])){
				if(!is_array($this->config[$Model->alias]['fields'])){
					$fields_to_encrypt = array($this->config[$Model->alias]['fields']);
				} else{
					$fields_to_encrypt = $this->config[$Model->alias]['fields'];
				}
			}
			$ignored_datatypes = array();
			if(!empty($this->config[$Model->alias]['disabledFields'])){
				if(!is_array($this->config[$Model->alias]['disabledFields'])){
					$ignored_datatypes = array($this->config[$Model->alias]['disabledFields']);
				} else{
					$ignored_datatypes = $this->config[$Model->alias]['fields'];
				}
			}

			$prefix = $this->config[$Model->alias]['prefix'];
			$prefixLen = strlen($prefix);

			foreach($fields_to_encrypt as $field){
				//if the data exists and is not already encrypted...
				// Initialize your values
				$datatype = array();
				$value = null;
				if(array_key_exists($field, $Model->data[$Model->alias])){
					// now you are sure that the data exists
					$datatype = $Model->_schema[$field]['type'];
					$value = $Model->data[$Model->alias][$field];
				}
				if(!empty($value)
				&& !$this->isEncrypted($value)
				&& !in_array($datatype, $ignored_datatypes)){
					$encrypted = $this->_encryptField($value, $datatype);
					if($encrypted){
						$Model->data[$Model->alias][$field] = $encrypted;
					}else{
						$this->log(__METHOD__." Could not encrypt{$Model->alias}::$field: '$value'");
						trigger_error('Unable to encrypt a value.', E_USER_WARNING);
						return false;
					}
				}
			}
		}
		return true;
	}

	/**
	 * Determines if a string value is already encrypted or not.
	 *
	 * @return boolean
	 * @param string $value
	 * @access public
	 */
	public function isEncrypted($value)
	{
		return (@substr($value, 0, strlen($this->config[$this->modelName]['prefix'])) == $this->config[$this->modelName]['prefix']);
	}

	/**
	 * Encrypts a singular value.
	 *
	 * @return string
	 * @param string $value
	 * @param string $type[optional]
	 * @access private
	 */
	private function _encryptField($value, $type = 'string')
	{
		if(strlen($value) > 0){
			$prefix = $this->config[$this->modelName]['prefix'];
			$prefixLen = strlen($prefix);
			//ignore boolean data types
			if($type != 'boolean' && substr($value, 0, $prefixLen) !== $prefix){
				$init = mcrypt_generic_init($this->resource, $this->config[$this->modelName]['key'], $this->config[$this->modelName]['iv']);
				if($init >= 0 && $init !== false){
					$encrypted_data = mcrypt_generic($this->resource, $value);
					mcrypt_generic_deinit($this->resource);
					if($type != 'binary'){
						return $prefix.bin2hex($encrypted_data);    //for storage in database? Might need suffix!
					}else{
						return $prefix.$encrypted_data;             //for storage in database? Might need suffix!
					}
				}else{
					//error in mcrypt initialization
					if($init == -3){
						//incorrect key length
						$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to an incorrect key size.');
						trigger_error('Unable to initialize mcrypt for decryption due to incorrect key size.', E_USER_WARNING);
					}else if($init == -4){
						//memory allocation
						$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to a memory allocation problem.');
						trigger_error('Unable to initialize mcrypt for decryption due to a memory allocation problem.', E_USER_WARNING);
					}else if($init === false){
						//incorrect parameters were passed
						$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to incorrect parameters being passed.');
						trigger_error('Unable to initialize mcrypt for decryption due to incorrect parameters being passed.', E_USER_WARNING);
					}else{
						//unknown error
						$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to AN UNKNOWN ERROR.');
						trigger_error('Unable to initialize mcrypt for decryption due to AN UNKNOWN ERROR.', E_USER_WARNING);
					}
				}
			}
		}
		return $value;
	}

	/**
	 * Used internally by the behavior to decrypt a singular value
	 *
	 * @return string
	 * @param string $value
	 * @param string $type[optional]
	 * @access private
	 */
	private function _decryptField($value, $type = 'string')
	{
		//ignore boolean data types
		if($type != 'boolean' && $this->isEncrypted($value)){
			$clean_data = '';
			//remove the prefix from $value
			$value = substr($value, strlen($this->config[$this->modelName]['prefix']));
			$init = mcrypt_generic_init($this->resource, $this->config[$this->modelName]['key'], $this->config[$this->modelName]['iv']);
			if($init >= 0 && $init !== false){
				if($type != 'binary'){
					$clean_data = trim(mdecrypt_generic($this->resource, $this->_hex2bin($value)));
				}else{
					$clean_data = trim(mdecrypt_generic($this->resource, $value));
				}
				mcrypt_generic_deinit($this->resource);
			}else{
				//error in mcrypt initialization
				if($init == -3){
					//incorrect key length
					$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to an incorrect key size.');
					trigger_error('Unable to initialize mcrypt for decryption due to incorrect key size.', E_USER_WARNING);
				}else if($init == -4){
					//memory allocation
					$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to a memory allocation problem.');
					trigger_error('Unable to initialize mcrypt for decryption due to a memory allocation problem.', E_USER_WARNING);
				}else if($init === false){
					//incorrect parameters were passed
					$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to incorrect parameters being passed.');
					trigger_error('Unable to initialize mcrypt for decryption due to incorrect parameters being passed.', E_USER_WARNING);
				}else{
					//unknown error
					$this->log(__METHOD__.' Could not initialize mcrypt for decryption due to AN UNKNOWN ERROR.');
					trigger_error('Unable to initialize mcrypt for decryption due to AN UNKNOWN ERROR.', E_USER_WARNING);
				}
			}
			return $clean_data;
		}
		return $value;
	}

	/**
	 * Used externally (from a controller or model) to give the ability to decrypt
	 * encrypted data manually.
	 *
	 * @return string
	 * @param object $Model Model using the behavior
	 * @access public
	 */
	public static function decrypt(&$Model) {
		$args = func_get_args();
		$value = $args[1];
		return $this->_decryptField($value);
	}

	/**
	 * Used externally (from a controller or model) to give the ability to encrypt
	 * data manually.
	 *
	 * @return string
	 * @param object $Model Model using the behavior
	 * @access public
	 */
	public function encrypt(&$Model) {
		$args = func_get_args();
		$value = $args[1];
		if(strlen($value) > 0){
			return $this->_encryptField($value);
		}else{
			return $value;
		}
	}

	/**
	 * Resets original associations on models that may have receive multiple,
	 * subsequent unbindings.
	 *
	 * @return mixed
	 * @param object $Model					Model using the behavior
	 * @param mixed $result					The result from the find operation
	 * @param boolean $primary[optional]	Whether the find is a primary find type
	 * @access public
	 */
	public function afterFind(Model $Model, $result, $primary = false){
		if(!$result || empty($this->config[$Model->alias]['fields'])){
			return $result;
		}

		if(!is_array($this->config[$Model->alias]['fields'])){
			$this->config[$Model->alias]['fields'] = array($this->config[$Model->alias]['fields']);
		}

		if($this->config[$Model->alias]['autoDecrypt']){
			if($primary){
				if(is_array($result)){
					$result = $this->_decryptArray($Model, $result);
				}else{
					//not sure if we'll ever get here...
				}
			}else{
				//check for a value's prefix in key/value to decrypt it
			}
		}
		return $result;
	}

	/**
	 * A recursive method to automatically decrypt values within a find() call's
	 * return result array structure.
	 *
	 * @return mixed
	 * @param object $values Find call's array structure and values
	 * @param object $curModel[optional] A variable that holds the data on
	 * 									 which model the recursive method is
	 * 									 currently iterating over
	 * @access private
	 */
	private function _decryptArray(Model $Model, $values, $curModel = null)
	{
		if (!is_array($values)) {
			return;
		} else if (empty($values)) {
			return $values;
		}
		$index = 0;
		foreach ($values as $key => $value) {
			if (is_array($value)) {
				$keys = array_keys($values);
				if(!is_numeric($keys[$index])){
					$curModel = $keys[$index];
				}
				$values[$key] = $this->_decryptArray($Model, $value, $curModel);
			}else{
				if (in_array($key, $this->config[$Model->alias]['fields']) && $curModel == $Model->alias) {
					$values[$key] = $this->_decryptField($value);
				} else if (in_array($curModel.'.'.$key, $this->config[$Model->alias]['fields'])) {
					$values[$key] = $this->_decryptField($value);
				}
			}
			$index++;
		}
		return $values;
	}

	/**
	 * A small novelty function for use with decrypting data.
	 *
	 * @return string A string representing the binary data
	 * @param string $source A string representing the hex source data
	 * @access protected
	 */
	protected function _hex2bin($source)
	{
		//Source: User comments from http://php.net/bin2hex
		$bin = '';
		$strlen = strlen($source);
		for($i = 0; $i < $strlen; $i = $i + 2){
			$bin .= chr(hexdec(substr($source, $i, 2)));
		}
		return $bin;
	}
}
