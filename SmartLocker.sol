pragma solidity >=0.5.7 <0.6.0;

import "./ECDSA.sol";

contract SmartLockerRegistrar {

    // forward registrar
    mapping(address=>bytes32) registrar;

    // reverse registrar
    mapping(bytes32=>address) reverseRegistrar;

    // fallback function (external non-payable)
    function() external {}

    // events
    event SmartLockerCreated(bytes32 name, address smartLockerAddress);

    // create new smart locker with given name and keyname (external payable)
    function createSmartLocker(bytes32 name, bytes32 keyname) external payable
        returns (address) {

        // require name not null
        require(name != bytes32(0));

        // require name not already exist
        require(reverseRegistrar[name] == address(0));

        // require keyname not null
        require(keyname != bytes32(0));

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
        returns (bytes32) {

        return registrar[smartLockerAddress];
    }

    // get the address of the smart locker with given name (external view)
    function getAddress(bytes32 name) external view
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
        bytes32 keyname;
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
    event KeyAdded(address key, bytes32 keyname);
    event KeyRemoved(address key);
    event KeyUpdated(address key, bytes32 keyname);
    event SignedExecuted(address from, address to, uint value, bytes data, uint256 nonce, uint gasPrice, uint gasLimit, bytes result);

    // only authorised keys or self modifier
    modifier onlyAuthorisedKeysOrSelf(address sender) {

        require(keys[sender].authorised || sender == address(this));
        _;
    }

    // fallback function (payable)
    function() external payable {}

    // constructor with given key and keyname (public payable)
    constructor(address key, bytes32 keyname) public payable {

        // require key not null
        require(key != address(0));

        // require keyname not null
        require(keyname != bytes32(0));

        // add the key
        _addKey(key, keyname);
    }

    // add authorisation for given key and keyname (external)
    function addKey(address key, bytes32 keyname) external
        onlyAuthorisedKeysOrSelf(msg.sender) {

        // require key not null
        require(key != address(0));

        // require key not already authorised
        require(!keys[key].authorised);

        // require keyname not null
        require(keyname != bytes32(0));

        // add the key
        _addKey(key, keyname);
    }

    // add authorisation for given key and keyname (internal)
    function _addKey(address key, bytes32 keyname) internal {

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

    // update the given key (external)
    function updateKey(address key, bytes32 keyname) external
        onlyAuthorisedKeysOrSelf(msg.sender) {

        // require keyname not null
        require(keyname != bytes32(0));

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

        // measure initial gas
        uint256 gasUsed = gasleft();

        // execute the transaction
        (bool success, bytes memory result) = to.call.value(value)(data);

        // calculate gas used
        gasUsed = gasUsed - gasleft();

        // require success
        require(success);

        // require gas used not over gas limit
        require(gasUsed <= gasLimit);

        // emit event
        emit SignedExecuted(address(this), to, value, data, nextNonce, gasPrice, gasLimit, result);

        // update the nonce
        nextNonce++;

        // refund the gas used plus overhead of 40,000 and 68 for each input byte
        msg.sender.transfer((gasUsed + 40000 + (msg.data.length * 68)) * gasPrice);

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
        returns (bytes32) {

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
