pragma solidity >=0.5.4 <0.6.0;

import "./ECDSA.sol";

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
    
    // use ECDSA library for recovering signatures of hashes
    using ECDSA for bytes32;

    // authorised keys
    mapping(address=>bool) keys;
    uint256 keyCount;

    // next transaction nonce
    uint256 nextNonce;
    
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
        require(!keys[key]);
        
        // add the key as an authorised key
        keys[key] = true;
        keyCount++;
    }

    // remove authorisation for given key (external)
    function removeKey(address key) external onlyAuthorisedKeys(msg.sender) {
        
        // require key already authorised
        require(keys[key]);
        
        // require key not the only authorised key
        require(keyCount > 1);
        
        // remove the key as an authorised key
        keys[key] = false;
        keyCount--;
    }
    
    // execute transactions if signed by authorised keys (external)
    function executeSigned(address to, uint256 value, bytes calldata data, bytes calldata signature) external
      onlyAuthorisedKeys(recoverSigner(address(this), to, value, data, nextNonce, signature)) {
        
        // execute the transaction and require success
        // solium-disable-next-line security/no-call-value
        require(to.call.value(value)(data));
        
        // update the nonce
        nextNonce++;
    }
    
    // recover the signer of a signed message (internal pure)
    function recoverSigner(address from, address to, uint256 value, bytes memory data, uint256 nonce, bytes memory signature) internal pure returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(from, to, value, data, nonce));
        return hash.toEthSignedMessageHash().recover(signature);
    }
    
    // is the given key an authorised key (external view)
    function isKey(address key) external view returns (bool) {
        return keys[key];
    }
    
    // get the count of keys (external view)
    function getKeyCount() external view returns (uint256) {
        return keyCount;
    }
    
    // get the next execution nonce (external view)
    function getNextNonce() external view returns (uint256) {
        return nextNonce;
    }
}
