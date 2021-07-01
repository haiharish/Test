# Creation of application by inheriting the base image
FROM baseimage:firstdocker

LABEL intTeam "haiharish13@gmail.com" "application image"

# Project config
ARG project_root=/usr/src/intfolder

# Creating project and temp directories
RUN mkdir -p ${project_root}

WORKDIR ${project_root}

COPY . .

WORKDIR ${project_root}/interview

# Installing the python packages
RUN pip3 install -r ../requirement.txt

EXPOSE 7000

# ENTRYPOINT ["python"]

CMD ["python", "app.py"]
