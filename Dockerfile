# Use an official image as the base image
FROM ubuntu:20.04

# Set the working directory
WORKDIR /app

# Copy the C++ source code to the container
COPY index.cpp .
COPY makefile .

# Install the build essentials package
RUN apt-get update && apt-get install -y build-essential
RUN sudo apt-get install libpcap-dev

# Compile the C++ source code
RUN make

# Run the C++ app when the container is launched
CMD ["./index"]
