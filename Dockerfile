# Use an official GCC runtime as a parent image
FROM gcc:latest

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Copy the patch file
COPY mongoose_patch.diff .

# Apply the patch
RUN patch lib/mongoose.c < mongoose_patch.diff

# Compile the C code with optimization and linker flags
RUN gcc -std=c11 -O3 -pthread -ffunction-sections -fdata-sections -fno-exceptions -flto -ffat-lto-objects -o announcement_api announcement_api.c lib/mongoose.c -I./lib -lm -Wl,--gc-sections

# Make port 5671 available to the world outside this container
EXPOSE 5671

# Run the executable
CMD ["./announcement_api"]
