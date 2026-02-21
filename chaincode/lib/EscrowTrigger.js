/**
 * EscrowTrigger.js — triggerPayout, triggerRefund, getEscrowStatus, startChallengeTimer
 * ТЗ раздел 4. Хранение в ledger.
 */
const { Contract } = require('fabric-contract-api');

const ESCROW_PREFIX = 'escrow:';

class EscrowTrigger extends Contract {
    async triggerPayout(ctx, jobId, workerId, amount) {
        const key = ESCROW_PREFIX + jobId;
        const escrow = { jobId, workerId, amount: parseInt(amount, 10), status: 'payout_triggered', at: new Date().toISOString() };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(escrow)));
        return JSON.stringify({ jobId, workerId, amount, status: 'payout_triggered' });
    }

    async triggerRefund(ctx, jobId, providerId, amount) {
        const key = ESCROW_PREFIX + jobId;
        const escrow = { jobId, providerId, amount: parseInt(amount, 10), status: 'refund_triggered', at: new Date().toISOString() };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(escrow)));
        return JSON.stringify({ jobId, providerId, amount, status: 'refund_triggered' });
    }

    async getEscrowStatus(ctx, jobId) {
        const key = ESCROW_PREFIX + jobId;
        const raw = await ctx.stub.getState(key);
        const escrow = raw && raw.length > 0 ? JSON.parse(raw.toString()) : { jobId, status: 'unknown' };
        return JSON.stringify({ jobId, status: escrow.status });
    }

    async startChallengeTimer(ctx, jobId, windowSeconds) {
        const key = ESCROW_PREFIX + jobId;
        let escrow = { jobId, status: 'challenge_started', windowSeconds: parseInt(windowSeconds, 10) };
        const raw = await ctx.stub.getState(key);
        if (raw && raw.length > 0) escrow = { ...JSON.parse(raw.toString()), ...escrow };
        escrow.challengeStartedAt = new Date().toISOString();
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(escrow)));
        return JSON.stringify({ jobId, windowSeconds, status: 'challenge_started' });
    }
}

module.exports = EscrowTrigger;
