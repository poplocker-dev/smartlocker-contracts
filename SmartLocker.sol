pragma solidity >=0.5.1 <0.6.0;

contract SmartLockerRegistrar {
    
    // forward registrar
    mapping(address=>string) registrar;

    // reverse registrar
    mapping(string=>address) reverseRegistrar;
    
    // fallback function (external non-payable)
    function() external {}

    // create new smart locker with given name (external payable)
    function createSmartLocker(string calldata name) external payable returns (address) {
        
        // require name not empty and no longer than 32 characters
        bytes memory nameBytes = bytes(name);
        require(nameBytes.length > 0 && nameBytes.length <= 32);
    
        // require name not already exist
        require(reverseRegistrar[name] == address(0));
    
        // deploy a new smart locker and send all value    
        SmartLocker smartLocker = (new SmartLocker).value(msg.value)(msg.sender);
        
        // register the smart locker address with the given name
        address smartLockerAddress = address(smartLocker);
        registrar[smartLockerAddress] = name;
        
        // add corresponding entry to the reverse registrar
        reverseRegistrar[name] = smartLockerAddress;
        
        // return the smart locker address
        return smartLockerAddress;
    }
    
    // get the name of the smart locker with given address (external view)
    function getName(address smartLockerAddress) external view returns (string memory) {
        return registrar[smartLockerAddress];
    }
    
    // get the address of the smart locker with given name (external view)
    function getAddress(string calldata name) external view returns (address) {
        return reverseRegistrar[name];
    }
}

contract SmartLocker {
    
    // transaction nonce
    uint256 nonce;
    
    // authorised keys
    mapping(address=>bool) keys;
    uint256 keyCount;

    // only authorised keys modifier
    modifier onlyAuthorisedKeys(address sender)
    {
        require(keys[sender]);
        _;
    }

    // fallback function (payable)
    function() external payable {}
    
    // constructor with given key (public payable)
    constructor(address key) public payable {
        
        // require key not null
        require(key != address(0));
        
        // add the key as an authorised key
        keys[key] = true;
        keyCount++;
    }
    
    // add authorisation for given key (external)
    function addKey(address key) external onlyAuthorisedKeys(msg.sender) {
        
        // require key not null
        require(key != address(0));

        // require key not already authorised
        require(keys[key] == false);
        
        // add the key as an authorised key
        keys[key] = true;
        keyCount++;
    }

    // remove authorisation for given key (external)
    function removeKey(address key) external onlyAuthorisedKeys(msg.sender) {
        
        // require key already authorised
        require(keys[key] == true);
        
        // require key not the only authorised key
        require(keyCount > 1);
        
        // remove the key as an authorised key
        keys[key] = false;
        keyCount--;
    }
    
    // TODO: execute messages signed by authorised keys (external)
    //function executeSigned() external onlyAuthorisedKeys(signer) returns (uint256) {
    //    return nonce++;
    //}
    
    // is the given key an authorised key (external view)
    function isKey(address key) external view returns (bool) {
        return keys[key];
    }
    
    // get the count of keys
    function getKeyCount() external view returns (uint256) {
        return keyCount;
    }
}
