# Drakon

**A serious safe contract for serious lenders using the EIP-1271 framework**

## How does it work?

Smart contract wallet that allows a manager to create loan offers across the various lending platforms using the EIP-1271 method (isValidSignature). The manager however cannot transfer the funds (NFT and ERC20) outside the safe. He can only originate loan offers.

The owner can:
- move back the funds (NFT and ERC20) back to its address
- change the owner and manager
- set the allowance to the different NFTFI protocol contracts

This stack allows to separate the manager role from the owner role which is interesting in the following cases:
- algorithmic lenders: the manager is defined from a private key sitting on a server. If the key is leaked the funds are safu. The owner should be a multi sig or a hardware wallet.
- fund: the owner is an entity overseeing the manager. That way funds can be deposited in a trustless manner by the LPs and managed by the manager.

## Set-up

```shell
$ forge build
```

## Tests

```shell
$ ./start_chain.sh
$ forge test
```

### Deploy

```shell
$ forge script 
```

