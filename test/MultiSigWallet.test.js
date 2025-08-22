const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MultiSigWallet", function () {
  let multiSigWallet;
  let owner1, owner2, owner3, nonOwner;
  let owners;
  let numConfirmationsRequired;

  beforeEach(async function () {
    [owner1, owner2, owner3, nonOwner] = await ethers.getSigners();
    
    owners = [owner1.address, owner2.address, owner3.address];
    numConfirmationsRequired = 2;

    const MultiSigWallet = await ethers.getContractFactory("MultiSigWallet");
    multiSigWallet = await MultiSigWallet.deploy(owners, numConfirmationsRequired, 0, "Test Wallet");
    await multiSigWallet.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the correct owners", async function () {
      const deployedOwners = await multiSigWallet.getOwners();
      expect(deployedOwners).to.deep.equal(owners);
    });

    it("Should set the correct number of required confirmations", async function () {
      const threshold = await multiSigWallet.numConfirmationsRequired();
      expect(threshold).to.equal(numConfirmationsRequired);
    });

    it("Should set owners correctly in mapping", async function () {
      expect(await multiSigWallet.isOwner(owner1.address)).to.be.true;
      expect(await multiSigWallet.isOwner(owner2.address)).to.be.true;
      expect(await multiSigWallet.isOwner(owner3.address)).to.be.true;
      expect(await multiSigWallet.isOwner(nonOwner.address)).to.be.false;
    });

    it("Should start with 0 transactions", async function () {
      const count = await multiSigWallet.transactionCount();
      expect(count).to.equal(0);
    });
  });

  describe("Deposits", function () {
    it("Should accept ETH deposits", async function () {
      const depositAmount = ethers.parseEther("1.0");
      const initialBalance = await multiSigWallet.getBalance();
      
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: depositAmount
      });

      const finalBalance = await multiSigWallet.getBalance();
      expect(finalBalance).to.equal(initialBalance + depositAmount);
    });

    it("Should emit Deposit event", async function () {
      const depositAmount = ethers.parseEther("0.5");
      
      await expect(owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: depositAmount
      })).to.emit(multiSigWallet, "Deposit")
        .withArgs(owner1.address, depositAmount, depositAmount);
    });
  });

  describe("Transaction Management", function () {
    const recipient = "0x1234567890123456789012345678901234567890";
    const amount = ethers.parseEther("0.1");
    const data = "0x";

    beforeEach(async function () {
      // Fund the wallet first
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });
    });

    it("Should allow owners to submit transactions", async function () {
      await expect(multiSigWallet.connect(owner1).submitTransaction(recipient, amount, data, false, 0))
        .to.emit(multiSigWallet, "SubmitTransaction")
        .withArgs(owner1.address, 0, recipient, amount, data, 0);

      const transaction = await multiSigWallet.getTransaction(0);
      expect(transaction.to).to.equal(recipient);
      expect(transaction.value).to.equal(amount);
      expect(transaction.data).to.equal(data);
      expect(transaction.executed).to.be.false;
      expect(transaction.numConfirmations).to.equal(0);
    });

    it("Should not allow non-owners to submit transactions", async function () {
      await expect(
        multiSigWallet.connect(nonOwner).submitTransaction(recipient, amount, data, false, 0)
      ).to.be.revertedWith("MultiSigWallet: caller is not an owner");
    });

    it("Should not allow submitting to zero address", async function () {
      await expect(
        multiSigWallet.connect(owner1).submitTransaction(ethers.ZeroAddress, amount, data, false, 0)
      ).to.be.revertedWith("MultiSigWallet: invalid destination address");
    });

    it("Should increment transaction count", async function () {
      await multiSigWallet.connect(owner1).submitTransaction(recipient, amount, data, false, 0);
      expect(await multiSigWallet.transactionCount()).to.equal(1);
    });
  });

  describe("Transaction Confirmation", function () {
    const recipient = "0x1234567890123456789012345678901234567890";
    const amount = ethers.parseEther("0.1");
    const data = "0x";

    beforeEach(async function () {
      // Fund the wallet and submit a transaction
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });
      await multiSigWallet.connect(owner1).submitTransaction(recipient, amount, data, false, 0);
    });

    it("Should allow owners to confirm transactions", async function () {
      await expect(multiSigWallet.connect(owner2).confirmTransaction(0))
        .to.emit(multiSigWallet, "ConfirmTransaction")
        .withArgs(owner2.address, 0);

      const transaction = await multiSigWallet.getTransaction(0);
      expect(transaction.numConfirmations).to.equal(1);
      expect(await multiSigWallet.isConfirmed(0, owner2.address)).to.be.true;
    });

    it("Should not allow non-owners to confirm transactions", async function () {
      await expect(
        multiSigWallet.connect(nonOwner).confirmTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: caller is not an owner");
    });

    it("Should not allow confirming non-existent transactions", async function () {
      await expect(
        multiSigWallet.connect(owner1).confirmTransaction(999)
      ).to.be.revertedWith("MultiSigWallet: transaction does not exist");
    });

    it("Should not allow confirming already executed transactions", async function () {
      // Confirm with enough owners to execute
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);
      await multiSigWallet.connect(owner1).executeTransaction(0);

      // Try to confirm executed transaction
      await expect(
        multiSigWallet.connect(owner2).confirmTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: transaction already executed");
    });

    it("Should not allow confirming already confirmed transactions", async function () {
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      
      await expect(
        multiSigWallet.connect(owner2).confirmTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: transaction already confirmed");
    });
  });

  describe("Transaction Execution", function () {
    const recipient = "0x1234567890123456789012345678901234567890";
    const amount = ethers.parseEther("0.1");
    const data = "0x";

    beforeEach(async function () {
      // Fund the wallet and submit a transaction
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });
      await multiSigWallet.connect(owner1).submitTransaction(recipient, amount, data, false, 0);
    });

    it("Should execute transaction with sufficient confirmations", async function () {
      const initialBalance = await multiSigWallet.getBalance();
      
      // Confirm with enough owners
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);

      // Execute transaction
      await expect(multiSigWallet.connect(owner1).executeTransaction(0))
        .to.emit(multiSigWallet, "ExecuteTransaction")
        .withArgs(owner1.address, 0);

      const transaction = await multiSigWallet.getTransaction(0);
      expect(transaction.executed).to.be.true;
      
      const finalBalance = await multiSigWallet.getBalance();
      expect(finalBalance).to.equal(initialBalance - amount);
    });

    it("Should not execute transaction without sufficient confirmations", async function () {
      // Only confirm with one owner (need 2)
      await multiSigWallet.connect(owner2).confirmTransaction(0);

      await expect(
        multiSigWallet.connect(owner1).executeTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: cannot execute transaction");
    });

    it("Should not allow non-owners to execute transactions", async function () {
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);

      await expect(
        multiSigWallet.connect(nonOwner).executeTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: caller is not an owner");
    });

    it("Should not allow executing already executed transactions", async function () {
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);
      await multiSigWallet.connect(owner1).executeTransaction(0);

      await expect(
        multiSigWallet.connect(owner1).executeTransaction(0)
      ).to.be.revertedWith("MultiSigWallet: transaction already executed");
    });
  });

  describe("Confirmation Revocation", function () {
    const recipient = "0x1234567890123456789012345678901234567890";
    const amount = ethers.parseEther("0.1");
    const data = "0x";

    beforeEach(async function () {
      // Fund the wallet and submit a transaction
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });
      await multiSigWallet.connect(owner1).submitTransaction(recipient, amount, data, false, 0);
      await multiSigWallet.connect(owner2).confirmTransaction(0);
    });

    it("Should allow owners to revoke confirmations", async function () {
      await expect(multiSigWallet.connect(owner2).revokeConfirmation(0))
        .to.emit(multiSigWallet, "RevokeConfirmation")
        .withArgs(owner2.address, 0);

      const transaction = await multiSigWallet.getTransaction(0);
      expect(transaction.numConfirmations).to.equal(0);
      expect(await multiSigWallet.isConfirmed(0, owner2.address)).to.be.false;
    });

    it("Should not allow non-owners to revoke confirmations", async function () {
      await expect(
        multiSigWallet.connect(nonOwner).revokeConfirmation(0)
      ).to.be.revertedWith("MultiSigWallet: caller is not an owner");
    });

    it("Should not allow revoking unconfirmed transactions", async function () {
      await expect(
        multiSigWallet.connect(owner3).revokeConfirmation(0)
      ).to.be.revertedWith("MultiSigWallet: transaction not confirmed");
    });
  });

  describe("Owner Management", function () {
    it("Should allow adding new owners", async function () {
      const newOwner = "0x1234567890123456789012345678901234567890";
      
      await expect(multiSigWallet.connect(owner1).addOwner(newOwner))
        .to.emit(multiSigWallet, "OwnerAdded")
        .withArgs(newOwner);

      expect(await multiSigWallet.isOwner(newOwner)).to.be.true;
      
      const allOwners = await multiSigWallet.getOwners();
      expect(allOwners).to.include(newOwner);
    });

    it("Should not allow adding zero address as owner", async function () {
      await expect(
        multiSigWallet.connect(owner1).addOwner(ethers.ZeroAddress)
      ).to.be.revertedWith("MultiSigWallet: invalid owner address");
    });

    it("Should not allow adding existing owner", async function () {
      await expect(
        multiSigWallet.connect(owner1).addOwner(owner2.address)
      ).to.be.revertedWith("MultiSigWallet: owner already exists");
    });

    it("Should allow removing owners", async function () {
      await expect(multiSigWallet.connect(owner1).removeOwner(owner3.address))
        .to.emit(multiSigWallet, "OwnerRemoved")
        .withArgs(owner3.address);

      expect(await multiSigWallet.isOwner(owner3.address)).to.be.false;
      
      const allOwners = await multiSigWallet.getOwners();
      expect(allOwners).to.not.include(owner3.address);
    });

    it("Should not allow removing the last owner", async function () {
      // Remove two owners first
      await multiSigWallet.connect(owner1).removeOwner(owner2.address);
      await multiSigWallet.connect(owner1).removeOwner(owner3.address);

      // Try to remove the last owner
      await expect(
        multiSigWallet.connect(owner1).removeOwner(owner1.address)
      ).to.be.revertedWith("MultiSigWallet: cannot remove last owner");
    });
  });

  describe("Threshold Management", function () {
    it("Should allow changing threshold", async function () {
      const newThreshold = 3;
      
      await expect(multiSigWallet.connect(owner1).changeThreshold(newThreshold))
        .to.emit(multiSigWallet, "ThresholdChanged")
        .withArgs(newThreshold);

      expect(await multiSigWallet.numConfirmationsRequired()).to.equal(newThreshold);
    });

    it("Should not allow invalid threshold values", async function () {
      // Too low
      await expect(
        multiSigWallet.connect(owner1).changeThreshold(0)
      ).to.be.revertedWith("MultiSigWallet: invalid threshold");

      // Too high
      await expect(
        multiSigWallet.connect(owner1).changeThreshold(4)
      ).to.be.revertedWith("MultiSigWallet: invalid threshold");
    });
  });

  describe("Pause Functionality", function () {
    it("Should allow pausing the contract", async function () {
      await multiSigWallet.connect(owner1).pause();
      expect(await multiSigWallet.paused()).to.be.true;
    });

    it("Should allow unpausing the contract", async function () {
      await multiSigWallet.connect(owner1).pause();
      await multiSigWallet.connect(owner1).unpause();
      expect(await multiSigWallet.paused()).to.be.false;
    });

    it("Should not allow operations when paused", async function () {
      await multiSigWallet.connect(owner1).pause();

      // Fund the wallet first
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });

      // Try to submit transaction when paused
      await expect(
        multiSigWallet.connect(owner1).submitTransaction(
          "0x1234567890123456789012345678901234567890",
          ethers.parseEther("0.1"),
          "0x",
          false,
          0
        )
      ).to.be.revertedWith("MultiSigWallet: contract is paused");
    });
  });

  describe("Edge Cases", function () {
    it("Should handle multiple transactions correctly", async function () {
      // Fund the wallet
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("2.0")
      });

      // Submit multiple transactions
      await multiSigWallet.connect(owner1).submitTransaction(
        "0x1234567890123456789012345678901234567890",
        ethers.parseEther("0.1"),
        "0x",
        false,
        0
      );
      await multiSigWallet.connect(owner2).submitTransaction(
        "0x1234567890123456789012345678901234567891",
        ethers.parseEther("0.2"),
        "0x",
        false,
        0
      );

      expect(await multiSigWallet.transactionCount()).to.equal(2);

      // Confirm and execute first transaction
      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);
      await multiSigWallet.connect(owner1).executeTransaction(0);

      // Second transaction should still be pending
      const tx1 = await multiSigWallet.getTransaction(0);
      const tx2 = await multiSigWallet.getTransaction(1);
      expect(tx1.executed).to.be.true;
      expect(tx2.executed).to.be.false;
    });

    it("Should handle failed transactions gracefully", async function () {
      // This test would require a contract that can fail
      // For now, we test the basic flow
      await owner1.sendTransaction({
        to: await multiSigWallet.getAddress(),
        value: ethers.parseEther("1.0")
      });

      await multiSigWallet.connect(owner1).submitTransaction(
        "0x1234567890123456789012345678901234567890",
        ethers.parseEther("0.1"),
        "0x",
        false,
        0
      );

      await multiSigWallet.connect(owner2).confirmTransaction(0);
      await multiSigWallet.connect(owner3).confirmTransaction(0);

      // Execute should succeed for valid transaction
      await expect(multiSigWallet.connect(owner1).executeTransaction(0))
        .to.emit(multiSigWallet, "ExecuteTransaction");
    });
  });
});
