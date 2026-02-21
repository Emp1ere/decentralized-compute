/**
 * Marketplace.js — listContract, getAvailableContracts, claimContract
 * ТЗ раздел 4. Хранение в ledger.
 */
const { Contract } = require('fabric-contract-api');

const CONTRACT_PREFIX = 'contract:';
const CLAIM_PREFIX = 'claim:';

class Marketplace extends Contract {
    async listContract(ctx, contractJson) {
        const contract = JSON.parse(contractJson);
        const id = contract.contractId || contract.contract_id;
        if (!id) throw new Error('contractId required');
        contract.status = 'listed';
        contract.listedAt = new Date().toISOString();
        await ctx.stub.putState(CONTRACT_PREFIX + id, Buffer.from(JSON.stringify(contract)));
        return JSON.stringify({ status: 'listed', contractId: id });
    }

    async getAvailableContracts(ctx) {
        const iter = await ctx.stub.getStateByRange(CONTRACT_PREFIX, CONTRACT_PREFIX + '\uffff');
        const contracts = [];
        for await (const kv of iter) {
            const c = JSON.parse(kv.value.toString());
            if (c.status === 'listed' || c.status === 'active') contracts.push(c);
        }
        return JSON.stringify(contracts);
    }

    async claimContract(ctx, contractId, workerId) {
        const key = CONTRACT_PREFIX + contractId;
        const raw = await ctx.stub.getState(key);
        if (!raw || raw.length === 0) throw new Error('Contract not found');
        const contract = JSON.parse(raw.toString());
        if (contract.claimedBy) throw new Error('Already claimed');
        contract.claimedBy = workerId;
        contract.status = 'claimed';
        contract.claimedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(contract)));
        await ctx.stub.putState(CLAIM_PREFIX + contractId, Buffer.from(JSON.stringify({ contractId, workerId, at: contract.claimedAt })));
        return JSON.stringify({ contractId, workerId, status: 'claimed' });
    }
}

module.exports = Marketplace;
