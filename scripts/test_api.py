#!/usr/bin/env python3
"""
Script para probar el API de detección de phishing con casos de ejemplo.
"""

import json
import sys
import time
from typing import Any, Dict

import requests

# Configuración
API_ENDPOINT = "http://localhost:8000/classify"
API_TOKEN = "your-api-token"  # Cambiar por tu token real


def load_test_cases() -> Dict[str, Any]:
    """Cargar casos de prueba desde el archivo JSON."""
    with open("examples/test_cases.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_classification(request_data: Dict[str, Any], token: str) -> Dict[str, Any]:
    """Enviar request de clasificación al API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    try:
        response = requests.post(
            API_ENDPOINT, headers=headers, json=request_data, timeout=10
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}", "detail": response.text}
    except Exception as e:
        return {"error": str(e)}


def print_result(test_name: str, expected: Dict[str, Any], actual: Dict[str, Any]):
    """Imprimir resultado de la prueba."""
    print(f"\n{'='*60}")
    print(f"🧪 TEST: {test_name}")
    print(f"{'='*60}")

    if "error" in actual:
        print(f"❌ ERROR: {actual['error']}")
        return False

    # Verificar clasificación
    expected_class = expected.get("classification", "unknown")
    actual_class = actual.get("classification", "unknown")

    class_match = expected_class == actual_class
    class_icon = "✅" if class_match else "❌"

    print(f"{class_icon} Clasificación: {actual_class} (esperada: {expected_class})")

    # Verificar score aproximado
    expected_score = expected.get("expected_score", 0)
    actual_score = actual.get("risk_score", 0)

    score_diff = abs(expected_score - actual_score)
    score_ok = score_diff <= 20  # Tolerancia de ±20 puntos
    score_icon = "✅" if score_ok else "⚠️"

    print(f"{score_icon} Puntuación: {actual_score}/100 (esperada: ~{expected_score})")

    # Mostrar resumen
    summary = actual.get("non_technical_summary", "No disponible")
    print(f"📝 Resumen: {summary}")

    # Mostrar razones
    reasons = actual.get("top_reasons", [])
    print(f"🔍 Razones principales:")
    for i, reason in enumerate(reasons[:3], 1):
        print(f"   {i}. {reason}")

    # Mostrar acciones
    actions = actual.get("recommended_actions", [])
    print(f"🛡️ Acciones recomendadas:")
    for i, action in enumerate(actions[:3], 1):
        print(f"   {i}. {action}")

    # Mostrar latencia
    latency = actual.get("latency_ms", 0)
    latency_ok = latency <= 3000  # SLO de 3 segundos
    latency_icon = "✅" if latency_ok else "⚠️"
    print(f"{latency_icon} Latencia: {latency}ms (SLO: ≤3000ms)")

    return class_match and score_ok


def run_test_suite():
    """Ejecutar suite completa de pruebas."""
    print("🚀 Iniciando pruebas del API de detección de phishing")
    print(f"📡 Endpoint: {API_ENDPOINT}")

    # Verificar conectividad
    try:
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        if health_response.status_code != 200:
            print("❌ El servicio no está disponible")
            sys.exit(1)
        print("✅ Servicio disponible")
    except Exception as e:
        print(f"❌ No se puede conectar al servicio: {e}")
        sys.exit(1)

    # Cargar casos de prueba
    try:
        test_cases = load_test_cases()
        print(
            f"📊 Cargados {sum(len(cases) for cases in test_cases.values())} casos de prueba"
        )
    except Exception as e:
        print(f"❌ Error cargando casos de prueba: {e}")
        sys.exit(1)

    # Ejecutar pruebas
    results = {"total": 0, "passed": 0, "failed": 0, "categories": {}}

    for category, cases in test_cases.items():
        print(f"\n🏷️ Categoría: {category.upper()}")
        category_results = {"total": 0, "passed": 0}

        for case in cases:
            test_name = case["name"]
            request_data = case["request"]
            expected = case

            start_time = time.time()
            actual = test_classification(request_data, API_TOKEN)
            test_time = time.time() - start_time

            success = print_result(test_name, expected, actual)

            results["total"] += 1
            category_results["total"] += 1

            if success:
                results["passed"] += 1
                category_results["passed"] += 1
            else:
                results["failed"] += 1

            print(f"⏱️ Tiempo de prueba: {test_time:.2f}s")

        results["categories"][category] = category_results
        print(
            f"📈 {category}: {category_results['passed']}/{category_results['total']} pruebas pasaron"
        )

    # Resumen final
    print(f"\n{'='*60}")
    print("📊 RESUMEN FINAL")
    print(f"{'='*60}")

    success_rate = (
        (results["passed"] / results["total"]) * 100 if results["total"] > 0 else 0
    )

    print(
        f"✅ Pruebas exitosas: {results['passed']}/{results['total']} ({success_rate:.1f}%)"
    )
    print(f"❌ Pruebas fallidas: {results['failed']}")

    for category, cat_results in results["categories"].items():
        cat_rate = (cat_results["passed"] / cat_results["total"]) * 100
        print(
            f"   {category}: {cat_results['passed']}/{cat_results['total']} ({cat_rate:.1f}%)"
        )

    if success_rate >= 80:
        print("\n🎉 ¡Suite de pruebas EXITOSA!")
        return 0
    else:
        print("\n⚠️ Algunas pruebas fallaron. Revisar logs.")
        return 1


if __name__ == "__main__":
    # Permitir override de configuración via argumentos
    if len(sys.argv) > 1:
        API_ENDPOINT = sys.argv[1]
    if len(sys.argv) > 2:
        API_TOKEN = sys.argv[2]

    exit_code = run_test_suite()
    sys.exit(exit_code)
