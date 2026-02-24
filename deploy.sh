#!/bin/bash

# Service Name
SERVICE_NAME="simple-oauth-app"
REGION="us-central1"

echo "Deploying $SERVICE_NAME to Cloud Run in region $REGION..."

# Deploy to Cloud Run

gcloud alpha run deploy simple-oauth-app  \
--image us-central1-docker.pkg.dev/g-sql-morphic-luminous/cloud-run-source-deploy/simple-oauth-app:latest   \
--iap   \
--service-account 'da-tco-app@g-sql-morphic-luminous.iam.gserviceaccount.com'  \
--project g-sql-morphic-luminous   \
--region us-central1  \
--no-allow-unauthenticated

echo "Deployment complete."
