/**
 * Reputation.js — recordResult, getReputation, slashReputation
 * ТЗ раздел 4. Хранение в ledger.
 */
const { Contract } = require('fabric-contract-api');

const REP_PREFIX = 'rep:';

class Reputation extends Contract {
    async recordResult(ctx, workerId, contractId, success) {
        const key = REP_PREFIX + workerId;
        let rep = { workerId, score: 0, results: [] };
        const raw = await ctx.stub.getState(key);
        if (raw && raw.length > 0) rep = JSON.parse(raw.toString());
        rep.results.push({ contractId, success, at: new Date().toISOString() });
        rep.score += success ? 1 : -1;
        rep.updatedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(rep)));
        return JSON.stringify({ workerId, contractId, success, score: rep.score });
    }

    async getReputation(ctx, workerId) {
        const key = REP_PREFIX + workerId;
        const raw = await ctx.stub.getState(key);
        const rep = raw && raw.length > 0 ? JSON.parse(raw.toString()) : { workerId, score: 0, results: [] };
        return JSON.stringify({ workerId, score: rep.score });
    }

    async slashReputation(ctx, workerId, amount, reason) {
        const key = REP_PREFIX + workerId;
        let rep = { workerId, score: 0, slashes: [] };
        const raw = await ctx.stub.getState(key);
        if (raw && raw.length > 0) rep = JSON.parse(raw.toString());
        rep.slashes = rep.slashes || [];
        rep.slashes.push({ amount, reason, at: new Date().toISOString() });
        rep.score = (rep.score || 0) - parseInt(amount, 10);
        rep.updatedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(rep)));
        return JSON.stringify({ workerId, amount, reason, score: rep.score });
    }
}

module.exports = Reputation;
