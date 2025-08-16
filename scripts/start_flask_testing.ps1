# scripts/start_flask_testing.ps1
# Inicia o servidor Flask em modo de teste (TESTING=1)
$env:FLASK_APP = "app.main:app"
$env:TESTING = "1"
python -m flask run --reload 