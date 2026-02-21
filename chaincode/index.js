/**
 * DSCM Chaincode (ADR 003) — Node.js
 * Модули: Marketplace, Contract, Reputation, EscrowTrigger
 * Каналы: public-marketplace, private-science
 *
 * Fabric deployCC: default contract = Marketplace
 */
const Marketplace = require('./lib/Marketplace');
const ContractModule = require('./lib/Contract');
const Reputation = require('./lib/Reputation');
const EscrowTrigger = require('./lib/EscrowTrigger');

module.exports.Marketplace = Marketplace;
module.exports.Contract = ContractModule;
module.exports.Reputation = Reputation;
module.exports.EscrowTrigger = EscrowTrigger;
module.exports.contracts = [Marketplace, ContractModule, Reputation, EscrowTrigger];
