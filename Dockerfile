# Use an official Python runtime as a base image
FROM python:3.9-slim

RUN apt-get update && apt-get install -y cron
# Install ps
RUN apt-get update && apt-get install -y procps

# Set the environment variable
ENV PS_FORMAT "pid,%cpu,%mem,cmd"

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install -r requirements.txt

# Copy the application code
COPY . .

# Expose the port
EXPOSE 8000




# Run the command to start the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Add a cron job to run a script every minute
RUN crontab -l | { cat; echo "*/2 * * * * /app/auto-discovery/venv/bin/python  /app/auto-discovery/manage.py runscript device_status >> /app/auto-discovery/logs/device-crontab.log 2>&1"; } | crontab -