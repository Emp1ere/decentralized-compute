"""
Модуль с разными типами вычислений для имитации астрофизических задач.
Каждый тип вычислений выполняет реалистичную симуляцию работы и возвращает детерминированный результат.
"""
import hashlib
import math
import random


def compute_cosmological_simulation(client_id, contract_id, work_units, seed=None):
    """
    Космологические симуляции: N-body задача (гравитационные взаимодействия).
    Симулирует взаимодействие частиц под действием гравитации.
    """
    if seed is None:
        seed = hash(f"{client_id}-{contract_id}") % (2**32)
    rng = random.Random(seed)
    
    # Инициализация частиц (упрощённая модель)
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
    
    # Симуляция гравитационных взаимодействий
    dt = 0.01
    total_energy = 0.0
    
    for step in range(work_units):
        # Вычисление сил гравитации между всеми парами частиц
        for i in range(n_particles):
            fx, fy, fz = 0.0, 0.0, 0.0
            for j in range(n_particles):
                if i == j:
                    continue
                dx = particles[j]['x'] - particles[i]['x']
                dy = particles[j]['y'] - particles[i]['y']
                dz = particles[j]['z'] - particles[i]['z']
                dist_sq = dx*dx + dy*dy + dz*dz + 0.01  # Мягкое ядро для стабильности
                dist = math.sqrt(dist_sq)
                force = particles[i]['mass'] * particles[j]['mass'] / (dist_sq * dist)
                fx += force * dx
                fy += force * dy
                fz += force * dz
            
            # Обновление скоростей
            particles[i]['vx'] += fx * dt / particles[i]['mass']
            particles[i]['vy'] += fy * dt / particles[i]['mass']
            particles[i]['vz'] += fz * dt / particles[i]['mass']
        
        # Обновление позиций
        for i in range(n_particles):
            particles[i]['x'] += particles[i]['vx'] * dt
            particles[i]['y'] += particles[i]['vy'] * dt
            particles[i]['z'] += particles[i]['vz'] * dt
        
        # Вычисление полной энергии (кинетическая + потенциальная)
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
    
    # Результат: хеш от финального состояния системы
    final_state = f"{particles[0]['x']:.6f}{particles[0]['y']:.6f}{total_energy:.6f}"
    result_hash = hashlib.sha256(final_state.encode()).hexdigest()
    return result_hash, str(seed)


def compute_supernova_modeling(client_id, contract_id, work_units, seed=None):
    """
    Моделирование сверхновых: радиационно-гидродинамический взрыв.
    Итеративное решение уравнений с конвергенцией.
    """
    if seed is None:
        seed = hash(f"{client_id}-{contract_id}") % (2**32)
    rng = random.Random(seed)
    
    # Начальные условия: температура, давление, плотность
    T = 1e9  # Температура в Кельвинах
    P = 1e15  # Давление
    rho = 1e6  # Плотность
    
    # Итеративное решение с конвергенцией
    for iteration in range(work_units):
        # Радиационный перенос (упрощённая модель)
        dT_dt = -0.1 * T * rho / (1.0 + T/1e8)
        dP_dt = -0.05 * P * T / 1e9
        
        # Гидродинамика (упрощённая модель)
        drho_dt = -0.02 * rho * math.sqrt(T/1e9)
        
        # Обновление состояния
        dt = 0.001
        T += dT_dt * dt
        P += dP_dt * dt
        rho += drho_dt * dt
        
        # Ограничения для стабильности
        T = max(T, 1e7)
        P = max(P, 1e10)
        rho = max(rho, 1e3)
        
        # Проверка конвергенции (каждые 1000 итераций)
        if iteration % 1000 == 0:
            convergence = abs(dT_dt) + abs(dP_dt) + abs(drho_dt)
            if convergence < 1e-6:
                break
    
    # Результат: хеш от финального состояния
    final_state = f"{T:.6e}{P:.6e}{rho:.6e}"
    result_hash = hashlib.sha256(final_state.encode()).hexdigest()
    return result_hash, str(seed)


def compute_mhd_jets(client_id, contract_id, work_units, seed=None):
    """
    МГД джетов и аккреции: магнитогидродинамика с адаптивными сетками.
    Матричные операции для решения уравнений МГД.
    """
    if seed is None:
        seed = hash(f"{client_id}-{contract_id}") % (2**32)
    rng = random.Random(seed)
    
    # Сетка 20x20x20 (упрощённая модель адаптивной сетки)
    grid_size = 20
    Bx = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    By = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    Bz = [[[rng.uniform(-1, 1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    vx = [[[rng.uniform(-0.1, 0.1) for _ in range(grid_size)] for _ in range(grid_size)] for _ in range(grid_size)]
    
    # Итеративное решение уравнений МГД
    for step in range(work_units):
        # Вычисление производных магнитного поля (упрощённая модель)
        for i in range(1, grid_size-1):
            for j in range(1, grid_size-1):
                for k in range(1, grid_size-1):
                    # Индукция (упрощённая модель)
                    dBx_dt = (Bx[i+1][j][k] - Bx[i-1][j][k]) / 2.0 * vx[i][j][k]
                    dBy_dt = (By[i][j+1][k] - By[i][j-1][k]) / 2.0 * vx[i][j][k]
                    dBz_dt = (Bz[i][j][k+1] - Bz[i][j][k-1]) / 2.0 * vx[i][j][k]
                    
                    # Обновление магнитного поля
                    dt = 0.001
                    Bx[i][j][k] += dBx_dt * dt
                    By[i][j][k] += dBy_dt * dt
                    Bz[i][j][k] += dBz_dt * dt
                    
                    # Обновление скорости (упрощённая модель)
                    dvx_dt = (Bx[i+1][j][k] - Bx[i-1][j][k]) / 2.0
                    vx[i][j][k] += dvx_dt * dt * 0.1
    
    # Результат: хеш от финального состояния магнитного поля
    final_state = f"{Bx[10][10][10]:.6f}{By[10][10][10]:.6f}{Bz[10][10][10]:.6f}"
    result_hash = hashlib.sha256(final_state.encode()).hexdigest()
    return result_hash, str(seed)


def compute_radiative_transfer(client_id, contract_id, work_units, seed=None):
    """
    Радиационный перенос: решение уравнения переноса излучения.
    Численное интегрирование по углам, частотам и пространственным координатам.
    """
    if seed is None:
        seed = hash(f"{client_id}-{contract_id}") % (2**32)
    rng = random.Random(seed)
    
    # Параметры: углы, частоты, пространственные координаты
    n_angles = 10
    n_frequencies = 20
    n_points = 50
    
    # Интенсивность излучения I(angle, frequency, position)
    I = [[[rng.uniform(0, 1) for _ in range(n_points)] for _ in range(n_frequencies)] for _ in range(n_angles)]
    
    # Численное интегрирование уравнения переноса
    for step in range(work_units):
        # Интегрирование по углам
        for angle_idx in range(n_angles):
            angle = angle_idx * math.pi / n_angles
            cos_angle = math.cos(angle)
            
            # Интегрирование по частотам
            for freq_idx in range(n_frequencies):
                frequency = freq_idx * 0.1
                
                # Интегрирование по пространственным координатам
                for pos_idx in range(1, n_points):
                    # Уравнение переноса (упрощённая модель)
                    dI_ds = -I[angle_idx][freq_idx][pos_idx] * (1.0 + frequency)
                    
                    # Источники излучения (упрощённая модель)
                    source = 0.1 * math.exp(-frequency) * (1.0 + cos_angle)
                    
                    # Обновление интенсивности
                    ds = 0.01
                    I[angle_idx][freq_idx][pos_idx] += (dI_ds + source) * ds
                    I[angle_idx][freq_idx][pos_idx] = max(0, I[angle_idx][freq_idx][pos_idx])
    
    # Результат: хеш от интеграла интенсивности по всем параметрам
    total_intensity = sum(sum(sum(row) for row in freq) for freq in I)
    final_state = f"{total_intensity:.6e}"
    result_hash = hashlib.sha256(final_state.encode()).hexdigest()
    return result_hash, str(seed)


def compute_gravitational_waves(client_id, contract_id, work_units, seed=None):
    """
    Гравитационные волны: численное решение уравнений Эйнштейна.
    Решение дифференциальных уравнений для метрики пространства-времени.
    """
    if seed is None:
        seed = hash(f"{client_id}-{contract_id}") % (2**32)
    rng = random.Random(seed)
    
    # Метрика пространства-времени (упрощённая модель: 2D)
    grid_size = 30
    h_plus = [[rng.uniform(-0.01, 0.01) for _ in range(grid_size)] for _ in range(grid_size)]
    h_cross = [[rng.uniform(-0.01, 0.01) for _ in range(grid_size)] for _ in range(grid_size)]
    
    # Решение уравнений Эйнштейна (волновое уравнение для гравитационных волн)
    dt = 0.001
    dx = 0.1
    
    for step in range(work_units):
        # Вычисление вторых производных (волновое уравнение)
        h_plus_new = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
        h_cross_new = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
        
        for i in range(1, grid_size-1):
            for j in range(1, grid_size-1):
                # Волновое уравнение: d²h/dt² = c²(d²h/dx² + d²h/dy²)
                d2h_dx2_plus = (h_plus[i+1][j] - 2*h_plus[i][j] + h_plus[i-1][j]) / (dx*dx)
                d2h_dy2_plus = (h_plus[i][j+1] - 2*h_plus[i][j] + h_plus[i][j-1]) / (dx*dx)
                d2h_dx2_cross = (h_cross[i+1][j] - 2*h_cross[i][j] + h_cross[i-1][j]) / (dx*dx)
                d2h_dy2_cross = (h_cross[i][j+1] - 2*h_cross[i][j] + h_cross[i][j-1]) / (dx*dx)
                
                # Обновление (упрощённая схема Эйлера)
                c_squared = 1.0
                h_plus_new[i][j] = h_plus[i][j] + dt * c_squared * (d2h_dx2_plus + d2h_dy2_plus)
                h_cross_new[i][j] = h_cross[i][j] + dt * c_squared * (d2h_dx2_cross + d2h_dy2_cross)
        
        h_plus = h_plus_new
        h_cross = h_cross_new
    
    # Результат: хеш от амплитуды гравитационной волны в центре
    amplitude = math.sqrt(h_plus[15][15]**2 + h_cross[15][15]**2)
    final_state = f"{amplitude:.6e}"
    result_hash = hashlib.sha256(final_state.encode()).hexdigest()
    return result_hash, str(seed)


def compute_simple_pow(client_id, contract_id, work_units, difficulty, seed=None):
    """
    Простой PoW: поиск хеша с нужным префиксом (для тестовых задач).
    """
    target_prefix = "0" * difficulty
    final_result = None
    solution_nonce = None
    
    for nonce in range(1, work_units + 1):
        text = f"{client_id}-{contract_id}-{nonce}"
        hash_result = hashlib.sha256(text.encode()).hexdigest()
        
        if hash_result.startswith(target_prefix):
            final_result = hash_result
            solution_nonce = str(nonce)
    
    return final_result or "", solution_nonce


# Реестр типов вычислений
COMPUTATION_TYPES = {
    "cosmological": compute_cosmological_simulation,
    "supernova": compute_supernova_modeling,
    "mhd": compute_mhd_jets,
    "radiative": compute_radiative_transfer,
    "gravitational_waves": compute_gravitational_waves,
    "simple_pow": compute_simple_pow,
}
