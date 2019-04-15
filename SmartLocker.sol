pragma solidity >=0.5.7 <0.6.0;

import "./ECDSA.sol";

contract SmartLockerRegistrar {

    // forward registrar
    mapping(address=>string) registrar;

    // reverse registrar
    mapping(string=>address) reverseRegistrar;

    // fallback function (external non-payable)
    function() external {}

    // events
    event SmartLockerCreated(string name, address smartLockerAddress);

    // valid name length modifier
    modifier validNameLength(string memory name) {

        bytes memory nameBytes = bytes(name);
        require(nameBytes.length > 0 && nameBytes.length <= 32);
        _;
    }

    // create new smart locker with given name and keyname (external payable)
    function createSmartLocker(string calldata name, string calldata keyname) external payable
        validNameLength(name)
        validNameLength(keyname)
        returns (address) {

        // require name not already exist
        require(reverseRegistrar[name] == address(0));

        // deploy a new smart locker and send all value
        SmartLocker smartLocker = (new SmartLocker).value(msg.value)(msg.sender, keyname);

        // register the smart locker address with the given name
        address smartLockerAddress = address(smartLocker);
        registrar[smartLockerAddress] = name;

        // add corresponding entry to the reverse registrar
        reverseRegistrar[name] = smartLockerAddress;

        // emit event
        emit SmartLockerCreated(name, smartLockerAddress);

        // return the smart locker address
        return smartLockerAddress;
    }

    // get the name of the smart locker with given address (external view)
    function getName(address smartLockerAddress) external view
        returns (string memory) {

        return registrar[smartLockerAddress];
    }

    // get the address of the smart locker with given name (external view)
    function getAddress(string calldata name) external view
        returns (address) {

        return reverseRegistrar[name];
    }
}

contract SmartLocker {

    // use ECDSA library for recovering signatures of hashes
    using ECDSA for bytes32;

    // Key
    struct Key {
        uint256 index;
        bool authorised;
        string keyname;
        // TODO: other attributes here, e.g. management flag, threshold
    }

    // keys
    mapping(address=>Key) keys;

    // authorised key count
    uint256 authorisedKeyCount;

    // key list
    address[] keyList;

    // next transaction nonce
    uint256 nextNonce;

    // events
    event KeyAdded(address key, string keyname);
    event KeyRemoved(address key);
    event KeyUpdated(address key, string keyname);
    event SignedExecuted(address from, address to, uint value, bytes data, uint256 nonce, uint gasPrice, uint gasLimit, bytes result);

    // valid name length modifier
    modifier validNameLength(string memory name) {

        bytes memory nameBytes = bytes(name);
        require(nameBytes.length > 0 && nameBytes.length <= 32);
        _;
    }

    // only authorised keys or self modifier
    modifier onlyAuthorisedKeysOrSelf(address sender) {

        require(keys[sender].authorised || sender == address(this));
        _;
    }

    // fallback function (payable)
    function() external payable {}

    // constructor with given key and keyname (public payable)
    constructor(address key, string memory keyname) public payable
        validNameLength(keyname) {

        // require key not null
        require(key != address(0));

        // add the key
        _addKey(key, keyname);
    }

    // add authorisation for given key and keyname (external)
    function addKey(address key, string calldata keyname) external
        validNameLength(keyname)
        onlyAuthorisedKeysOrSelf(msg.sender) {

        // require key not null
        require(key != address(0));

        // require key not already authorised
        require(!keys[key].authorised);

        // add the key
        _addKey(key, keyname);
    }

    // add authorisation for given key and keyname (internal)
    function _addKey(address key, string memory keyname) internal {

        // add the key as an authorised key
        keys[key].index = keyList.length;
        keys[key].authorised = true;
        keys[key].keyname = keyname;
        authorisedKeyCount++;

        // add to the key list
        keyList.push(key);

        // emit event
        emit KeyAdded(key, keyname);
    }

    // remove authorisation for given key (external)
    function removeKey(address key) external
        onlyAuthorisedKeysOrSelf(msg.sender) {

        // require key already authorised
        require(keys[key].authorised);

        // require key not the only authorised key
        require(authorisedKeyCount > 1);

        // remove the key as an authorised key
        keys[key].authorised = false;
        authorisedKeyCount--;

        // delete from the key list
        delete keyList[keys[key].index];

        // emit event
        emit KeyRemoved(key);
    }

    function updateKey(address key, string calldata keyname) external
        validNameLength(keyname)
        onlyAuthorisedKeysOrSelf(msg.sender) {

        // update the key
        keys[key].keyname = keyname;
        // TODO: other attributes here, e.g. management flag, threshold

        // emit event
        emit KeyUpdated(key, keyname);
    }

    // execute transactions if signed by authorised keys (external)
    function executeSigned(address to, uint value, bytes calldata data, uint gasPrice, uint gasLimit, bytes calldata signature) external
        onlyAuthorisedKeysOrSelf(_recoverSigner(address(this), to, value, data, nextNonce, gasPrice, gasLimit, signature))
        returns (bytes memory) {

        // execute the transaction
        (bool success, bytes memory result) = to.call.value(value)(data);

        // require success
        require(success);

        // TODO: check gas used in call not over gasLimit
        // TODO: refund total gas used using gasPrice
        // NOTE: gas relayers should first check for failing tx

        // emit event
        emit SignedExecuted(address(this), to, value, data, nextNonce, gasPrice, gasLimit, result);

        // update the nonce
        nextNonce++;

        // return the result
        return result;
    }

    // recover the signer of a signed message (internal pure)
    function _recoverSigner(address from, address to, uint value, bytes memory data, uint256 nonce, uint gasPrice, uint gasLimit, bytes memory signature) internal pure
        returns (address) {

        bytes32 hash = keccak256(abi.encodePacked(from, to, value, data, nonce, gasPrice, gasLimit));
        return hash.toEthSignedMessageHash().recover(signature);
    }

    // is the given key an authorised key (external view)
    function isAuthorisedKey(address key) external view
        returns (bool) {

        return keys[key].authorised;
    }

    // get the given key (external view)
    function getKey(address key) external view
        returns (string memory) {

        return keys[key].keyname;
        // TODO: other attributes here, e.g. management flag, threshold
    }

    // get the count of keys (external view)
    function getAuthorisedKeyCount() external view
        returns (uint256) {

        return authorisedKeyCount;
    }

    // get the key list (external view)
    function getKeyList() external view
        returns (address[] memory) {

        return keyList;
    }

    // get the next execution nonce (external view)
    function getNextNonce() external view
        returns (uint256) {

        return nextNonce;
    }
}
