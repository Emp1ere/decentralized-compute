"""
Workload presets for applied-compute marketplace:
- domain-oriented contract templates;
- artifact format catalog (inputs/outputs);
- chunking hints for splitting large tasks into jobs.
"""

from copy import deepcopy


WORKLOAD_PRESETS = {
    "scientific_simulation_climate": {
        "title": "Scientific simulation (climate/astrophysics)",
        "task_class": "scientific_simulation",
        "task_category": "Scientific Simulation",
        "recommended_computation_type": "cosmological",
        "benchmark_meta": {
            "domain": "climate_simulation",
            "input_artifacts": [
                {"name": "initial_conditions", "formats": ["nc", "h5", "json"]},
                {"name": "model_params", "formats": ["yaml", "json"]},
            ],
            "output_artifacts_spec": [
                {"name": "state_snapshot", "formats": ["nc", "h5"], "required": True},
                {"name": "run_metrics", "formats": ["json", "csv"], "required": True},
            ],
            "chunking": {
                "strategy": "time_window",
                "chunk_unit": "hours",
                "chunk_size": 6,
                "recommended_parallel_jobs": 8,
            },
            "requirements": {"min_cpu_cores": 8, "min_ram_gb": 16, "require_gpu": False},
        },
    },
    "biomedical_protein_modeling": {
        "title": "Biomedical modeling (protein structure)",
        "task_class": "biomedical_modeling",
        "task_category": "Biomedical Modeling",
        "recommended_computation_type": "molecular_dynamics_benchpep",
        "benchmark_meta": {
            "domain": "protein_structure",
            "input_artifacts": [
                {"name": "sequence_or_seed", "formats": ["fasta", "pdb", "json"]},
                {"name": "constraints", "formats": ["json", "yaml"]},
            ],
            "output_artifacts_spec": [
                {"name": "predicted_structure", "formats": ["pdb", "cif"], "required": True},
                {"name": "confidence_report", "formats": ["json"], "required": True},
            ],
            "chunking": {
                "strategy": "candidate_batch",
                "chunk_unit": "candidates",
                "chunk_size": 32,
                "recommended_parallel_jobs": 4,
            },
            "requirements": {"min_cpu_cores": 8, "min_ram_gb": 24, "require_gpu": True},
        },
    },
    "ai_llm_inference_batch": {
        "title": "AI/LLM inference batch",
        "task_class": "ai_training",
        "task_category": "AI Inference",
        "recommended_computation_type": "simple_pow",
        "benchmark_meta": {
            "domain": "llm_inference",
            "input_artifacts": [
                {"name": "prompts", "formats": ["jsonl", "csv"]},
                {"name": "model_ref", "formats": ["json", "yaml"]},
            ],
            "output_artifacts_spec": [
                {"name": "generations", "formats": ["jsonl"], "required": True},
                {"name": "inference_metrics", "formats": ["json"], "required": True},
            ],
            "chunking": {
                "strategy": "batch",
                "chunk_unit": "requests",
                "chunk_size": 256,
                "recommended_parallel_jobs": 6,
            },
            "requirements": {"min_cpu_cores": 4, "min_ram_gb": 8, "require_gpu": True},
        },
    },
    "data_analytics_risk": {
        "title": "Data analytics and risk",
        "task_class": "data_analytics",
        "task_category": "Data Analytics",
        "recommended_computation_type": "supernova",
        "benchmark_meta": {
            "domain": "risk_analysis",
            "input_artifacts": [
                {"name": "timeseries", "formats": ["csv", "parquet"]},
                {"name": "scenario_config", "formats": ["json", "yaml"]},
            ],
            "output_artifacts_spec": [
                {"name": "risk_report", "formats": ["json", "csv"], "required": True},
                {"name": "diagnostics", "formats": ["json"], "required": False},
            ],
            "chunking": {
                "strategy": "partition",
                "chunk_unit": "rows",
                "chunk_size": 100000,
                "recommended_parallel_jobs": 8,
            },
            "requirements": {"min_cpu_cores": 4, "min_ram_gb": 8, "require_gpu": False},
        },
    },
}


def list_workload_presets():
    rows = []
    for preset_id, preset in WORKLOAD_PRESETS.items():
        row = deepcopy(preset)
        row["preset_id"] = preset_id
        rows.append(row)
    rows.sort(key=lambda x: x["preset_id"])
    return rows


def get_workload_preset(preset_id):
    preset = WORKLOAD_PRESETS.get((preset_id or "").strip())
    if not preset:
        return None
    return deepcopy(preset)
