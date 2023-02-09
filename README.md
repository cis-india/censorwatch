# CensorWatch

This repository hosts the website for CensorWatch (CIS' project to map net neutrality violations and web censorship in India), the data collected through the project and the scripts used to analyse the data

To download the data, visit the Releases section of this repository.

To import the data (using Mongo DB), extract the zip archive and inside the directory run `mongorestore --db log_database`.

To analyse the data (using R), see the `analysis_scripts` directory. `connect.R` and `query1.R` are useful starting points.
