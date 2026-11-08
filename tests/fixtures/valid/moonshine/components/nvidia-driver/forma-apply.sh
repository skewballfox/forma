#!/bin/sh
# Materia runs this as SetupScript and PostScript, while it holds its lock.
exec forma apply nvidia-driver --materia-lock held
