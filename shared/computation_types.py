"""
Единый модуль вычислений для оркестратора и воркера.
Один источник правды: одинаковый код и детерминированный seed (SHA256) для строгой верификации.

Правило для всех типов контрактов: result_data (proof) должен быть уникален по client_id,
т.е. в хеш или в входные данные результата всегда включается client_id. Иначе у разных
клиентов при одинаковом seed получится один proof и сдача будет отклоняться как «proof already used».
"""
import hashlib
import math
import random

# Диапазон seed для валидации на оркестраторе (защита от переполнения и DoS).
# 64 бит — чтобы коллизии между разными клиентами были практически невозможны (proof already used).
SEED_MIN = 0
SEED_MAX = (1 << 64) - 1


def deterministic_seed(client_id, contract_id):
    """
    Детерминированный seed из client_id и contract_id.
    Одинаковый результат у воркера и оркестратора (SHA256, не hash()).
    Возвращает int в [0, 2**32-1].
    """
    raw = f"{client_id}-{contract_id}".encode()
    h = hashlib.sha256(raw).hexdigest()
    return int(h[:8], 16) % (2**32)


def compute_cosmological_simulation(client_id, contract_id, work_units, seed=None, progress_callback=None):
    """
    Космологические симуляции: N-body задача (гравитационные взаимодействия).
    Начальное состояние частиц от rng(seed) — разный task_seed даёт разный результат (защита от replay).
    """
    if seed is None:
        seed = deterministic_seed(client_id, contract_id)
    rng = random.Random(seed)

    n_particles = 100
    particles = []
    for i in range(n_particles):
        particles.append({
            'x': rng.uniform(-1, 1),
            'y': rng.uniform(-1, 1),
            'z': rng.uniform(-1, 1),
            'vx': rng.uniform(-0.1, 0.1),
            'vy': rng.uniform(-0.1, 0.1),
            'vz': rng.uniform(-0.1, 0.1),
            'mass': rng.uniform(0.5, 2.0)
        })

    dt = 0.01
    total_energy = 0.0

    for step in range(work_units):
        if step and step % 10000 == 0 and progress_callback:
            progress_callback(step, work_units)
        for i in range(n_particles):
            fx, fy, fz = 0.0, 0.0, 0.0
            for j in range(n_particles):
                if i == j:
                    continue
                dx = particles[j]['x'] - particles[i]['x']
                dy = particles[j]['y'] - particles[i]['y']
                dz = particles[j]['z'] - particles[i]['z']
                dist_sq = dx*dx + dy*dy + dz*dz + 0.01
                dist = math.sqrt(dist_sq)
                force = particles[i]['mass'] * particles[j]['mass'] / (dist_sq * dist)
                fx += force * dx
                fy += force * dy
                fz += force * dz

            particles[i]['vx'] += fx * dt / particles[i]['mass']
            particles[i]['vy'] += fy * dt / particles[i]['mass']
            particles[i]['vz'] += fz * dt / particles[i]['mass']

        for i in range(n_particles):
            particles[i]['x'] += particles[i]['vx'] * dt
            particles[i]['y'] += particles[i]['vy'] * dt
            particles[i]['z'] += particles[i]['vz'] * dt

        if step % 100 == 0:
            ke = sum(0.5 * p['mass'] * (p['vx']**2 + p['vy']**2 + p['vz']**2) for p in particles)
            pe = 0.0
            for i in range(n_particles):
                for j in range(i+1, n_particles):
                    dx = particles[j]['x'] - particles[i]['x']
                    dy = particles[j]['y'] - particles[i]['y']
                    dz = particles[j]['z'] - particles[i]['z']
                    dist = math.sqrt(dx*dx + dy*dy + dz*dz + 0.01)
                    pe -= particles[i]['mass'] * particles[j]['mass'] / dist
            total_energy = ke + pe

    final_state = f"{particles[0]['x']:.6f}{particles[0]['y']:.6f}{total_energy:.6f}"
    # Включаем client_id в хеш: у разных клиентов разный result_data даже при одинаковом seed (нет «proof already used»).
    result_hash = hashlib.sha256((client_id + "|" + final_state).encode()).hexdigest()
    return result_hash, str(seed)


def compute_supernova_modeling(client_id, contract_id, work_units, seed=None, progress_callback=None):
    """Моделирование сверхновых: радиационно-гидродинамический взрыв."""
    if seed is None:
        seed = deterministic_seed(client_id, contract_id)
    rng = random.Random(seed)
    # Начальное состояние зависит от seed, иначе при любом seed результат один и тот же (replay).
    T = 1e9 * (1.0 + rng.uniform(-0.02, 0.02))
    P = 1e15 * (1.0 + rng.uniform(-0.02, 0.02))
    rho = 1e6 * (1.0 + rng.uniform(-0.02, 0.02))

    for iteration in range(work_units):
        if iteration and iteration % 10000 == 0 and progress_callback:
            progress_callback(iteration, work_units)
        dT_dt = -0.1 * T * rho / (1.0 + T/1e8)
        dP_dt = -0.05 * P * T / 1e9
        drho_dt = -0.02 * rho * math.sqrt(T/1e9)
        dt = 0.001
        T += dT_dt * dt
        P += dP_dt * dt
        rho += drho_dt * dt
        T = max(T, 1e7)
        P = max(P, 1e10)
        rho = max(rho, 1e3)
        if iteration % 1000 == 0:
            convergence = abs(dT_dt) + abs(dP_dt) + abs(drho_dt)
            if convergence < 1e-6:
                break

    final_state = f"{T:.6e}{P:.6e}{rho:.6e}"
    result_hash = hashlib.sha256((client_id + "|" + final_state).encode()).hexdigest()
    return result_hash, str(seed)


def compute_mhd_jets(client_id, contract_id, work_units, seed=None, progress_callback=None):
    """МГД джетов и аккреции. Начальные Bx,By,Bz,vx от rng(seed) — разный task_seed даёт разный результат (защита от replay)."""
    if seed is None:
        seed = deterministic_seed(client_id, contract_id)
    rng = random.Random(seed)

    grid_size = 20
    Bx = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    By = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    Bz = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    vx = [[[rng.uniform(-0.1, 0.1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]

    for step in range(work_units):
        if step and step % 10000 == 0 and progress_callback:
            progress_callback(step, work_units)
        for i in range(1, grid_size-1):
            for j in range(1, grid_size-1):
                for k in range(1, grid_size-1):
                    dBx_dt = (Bx[i+1][j][k] - Bx[i-1][j][k]) / 2.0 * vx[i][j][k]
                    dBy_dt = (By[i][j+1][k] - By[i][j-1][k]) / 2.0 * vx[i][j][k]
                    dBz_dt = (Bz[i][j][k+1] - Bz[i][j][k-1]) / 2.0 * vx[i][j][k]
                    dt = 0.001
                    Bx[i][j][k] += dBx_dt * dt
                    By[i][j][k] += dBy_dt * dt
                    Bz[i][j][k] += dBz_dt * dt
                    dvx_dt = (Bx[i+1][j][k] - Bx[i-1][j][k]) / 2.0
                    vx[i][j][k] += dvx_dt * dt * 0.1

    final_state = f"{Bx[10][10][10]:.6f}{By[10][10][10]:.6f}{Bz[10][10][10]:.6f}"
    result_hash = hashlib.sha256((client_id + "|" + final_state).encode()).hexdigest()
    return result_hash, str(seed)


def compute_radiative_transfer(client_id, contract_id, work_units, seed=None, progress_callback=None):
    """Радиационный перенос. Начальная интенсивность I от rng(seed) — разный task_seed даёт разный результат (защита от replay)."""
    if seed is None:
        seed = deterministic_seed(client_id, contract_id)
    rng = random.Random(seed)

    n_angles, n_frequencies, n_points = 10, 20, 50
    I = [[[rng.uniform(0, 1) for _ in range(n_points)] for _ in range(n_frequencies)] for _ in range(n_angles)]

    for step in range(work_units):
        if step and step % 10000 == 0 and progress_callback:
            progress_callback(step, work_units)
        for angle_idx in range(n_angles):
            angle = angle_idx * math.pi / n_angles
            cos_angle = math.cos(angle)
            for freq_idx in range(n_frequencies):
                frequency = freq_idx * 0.1
                for pos_idx in range(1, n_points):
                    dI_ds = -I[angle_idx][freq_idx][pos_idx] * (1.0 + frequency)
                    source = 0.1 * math.exp(-frequency) * (1.0 + cos_angle)
                    ds = 0.01
                    I[angle_idx][freq_idx][pos_idx] += (dI_ds + source) * ds
                    I[angle_idx][freq_idx][pos_idx] = max(0, I[angle_idx][freq_idx][pos_idx])

    total_intensity = sum(sum(sum(row) for row in freq) for freq in I)
    final_state = f"{total_intensity:.6e}"
    result_hash = hashlib.sha256((client_id + "|" + final_state).encode()).hexdigest()
    return result_hash, str(seed)


def compute_gravitational_waves(client_id, contract_id, work_units, seed=None, progress_callback=None):
    """Гравитационные волны. Начальные h_plus, h_cross от rng(seed) — разный task_seed даёт разный результат (защита от replay)."""
    if seed is None:
        seed = deterministic_seed(client_id, contract_id)
    rng = random.Random(seed)

    grid_size = 30
    h_plus = [[rng.uniform(-0.01, 0.01) for _ in range(grid_size)] for _ in range(grid_size)]
    h_cross = [[rng.uniform(-0.01, 0.01) for _ in range(grid_size)] for _ in range(grid_size)]

    dt, dx = 0.001, 0.1

    for step in range(work_units):
        if step and step % 10000 == 0 and progress_callback:
            progress_callback(step, work_units)
        h_plus_new = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
        h_cross_new = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
        for i in range(1, grid_size-1):
            for j in range(1, grid_size-1):
                d2h_dx2_plus = (h_plus[i+1][j] - 2*h_plus[i][j] + h_plus[i-1][j]) / (dx*dx)
                d2h_dy2_plus = (h_plus[i][j+1] - 2*h_plus[i][j] + h_plus[i][j-1]) / (dx*dx)
                d2h_dx2_cross = (h_cross[i+1][j] - 2*h_cross[i][j] + h_cross[i-1][j]) / (dx*dx)
                d2h_dy2_cross = (h_cross[i][j+1] - 2*h_cross[i][j] + h_cross[i][j-1]) / (dx*dx)
                c_squared = 1.0
                h_plus_new[i][j] = h_plus[i][j] + dt * c_squared * (d2h_dx2_plus + d2h_dy2_plus)
                h_cross_new[i][j] = h_cross[i][j] + dt * c_squared * (d2h_dx2_cross + d2h_dy2_cross)
        h_plus, h_cross = h_plus_new, h_cross_new

    amplitude = math.sqrt(h_plus[15][15]**2 + h_cross[15][15]**2)
    final_state = f"{amplitude:.6e}"
    result_hash = hashlib.sha256((client_id + "|" + final_state).encode()).hexdigest()
    return result_hash, str(seed)


def compute_simple_pow(client_id, contract_id, work_units, difficulty, seed=None):
    """Простой PoW: поиск хеша с нужным префиксом. Порядок перебора nonce зависит от seed — разный task_seed даёт разный результат (защита от replay). Result уже привязан к client_id (text = client_id-contract_id-nonce)."""
    target_prefix = "0" * difficulty
    final_result, solution_nonce = None, None
    # Порядок перебора nonce зависит от seed, иначе при том же контракте всегда находим один и тот же nonce → replay.
    if seed is not None:
        try:
            s = int(seed) & 0x7FFFFFFF
        except (TypeError, ValueError):
            s = 0
        max_nonce = max(work_units * 2, 10000)
        for i in range(work_units):
            nonce = 1 + (s * 31 + i) % max_nonce
            # client_id в строке хеша — proof уникален на клиента (как и у остальных контрактов).
            text = f"{client_id}-{contract_id}-{nonce}"
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            if hash_result.startswith(target_prefix):
                final_result = hash_result
                solution_nonce = str(nonce)
                break
    else:
        for nonce in range(1, work_units + 1):
            # client_id в строке хеша — proof уникален на клиента.
            text = f"{client_id}-{contract_id}-{nonce}"
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            if hash_result.startswith(target_prefix):
                final_result = hash_result
                solution_nonce = str(nonce)
                break
    return final_result or "", solution_nonce


COMPUTATION_TYPES = {
    "cosmological": compute_cosmological_simulation,
    "supernova": compute_supernova_modeling,
    "mhd": compute_mhd_jets,
    "radiative": compute_radiative_transfer,
    "gravitational_waves": compute_gravitational_waves,
    "simple_pow": compute_simple_pow,
}
