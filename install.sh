#!/bin/bash
declare -r STEPS=('step1' 'step2' 'step3' 'step4')
declare -r MAX_STEPS=${#STEPS[@]}
declare -r BAR_SIZE="##############"
declare -r MAX_BAR_SIZE=${#BAR_SIZE}

echo "Instalação do Skull-flash";

for step in "${!STEPS[@]}"; do
    perc=$(((step + 1) * 100 / MAX_STEPS))
    percBar=$((perc * MAX_BAR_SIZE / 100))
    sleep 0.5
    echo "[${BAR_SIZE:0:percBar}] $perc %"
done
echo ""

python -m venv venv

source venv/bin/activate

# Install with dev extras for testing/linting
pip install -e ".[dev]"

echo ""
echo "Instalação concluída. Use './run.sh --help' para ver os comandos disponíveis."