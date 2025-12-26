bandit src -r -v -n 3 --severity-level=all
pylint src/**/*py --py-version "3.11"
isort --check-only src --profile black
