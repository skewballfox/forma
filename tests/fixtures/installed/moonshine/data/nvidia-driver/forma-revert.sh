#!/bin/sh
# Materia runs this as CleanupScript, after it stops the services.
exec forma revert nvidia-driver --materia-lock held
