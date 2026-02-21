/**
 * Contract.js — activateContract, submitWork, verifyWork, completeContract, disputeContract
 * ТЗ раздел 4. Работа с ledger.
 */
const { Contract } = require('fabric-contract-api');

const JOB_PREFIX = 'job:';
const WORK_PREFIX = 'work:';

class ContractModule extends Contract {
    async activateContract(ctx, contractId) {
        const key = 'contract:' + contractId;
        const raw = await ctx.stub.getState(key);
        if (!raw || raw.length === 0) throw new Error('Contract not found');
        const c = JSON.parse(raw.toString());
        c.status = 'active';
        c.activatedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(c)));
        return JSON.stringify({ contractId, status: 'active' });
    }

    async submitWork(ctx, contractId, jobId, resultHash) {
        const key = WORK_PREFIX + contractId + ':' + jobId;
        const work = { contractId, jobId, resultHash, status: 'submitted', at: new Date().toISOString() };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(work)));
        return JSON.stringify({ contractId, jobId, resultHash, status: 'submitted' });
    }

    async verifyWork(ctx, contractId, jobId) {
        const key = WORK_PREFIX + contractId + ':' + jobId;
        const raw = await ctx.stub.getState(key);
        if (!raw || raw.length === 0) throw new Error('Work not found');
        const w = JSON.parse(raw.toString());
        w.status = 'verified';
        w.verifiedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(w)));
        return JSON.stringify({ contractId, jobId, status: 'verified' });
    }

    async completeContract(ctx, contractId) {
        const key = 'contract:' + contractId;
        const raw = await ctx.stub.getState(key);
        if (!raw || raw.length === 0) throw new Error('Contract not found');
        const c = JSON.parse(raw.toString());
        c.status = 'completed';
        c.completedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(c)));
        return JSON.stringify({ contractId, status: 'completed' });
    }

    async disputeContract(ctx, contractId, jobId, reason) {
        const key = WORK_PREFIX + contractId + ':' + jobId;
        const raw = await ctx.stub.getState(key);
        if (!raw || raw.length === 0) throw new Error('Work not found');
        const w = JSON.parse(raw.toString());
        w.status = 'disputed';
        w.disputeReason = reason;
        w.disputedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(w)));
        return JSON.stringify({ contractId, jobId, reason, status: 'disputed' });
    }
}

module.exports = ContractModule;
