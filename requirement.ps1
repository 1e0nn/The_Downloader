function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        #Write-Host "This script must be run as an administrator." -ForegroundColor Yellow
        return #mettre  exit 1 plus tard
    }
}

function Test-InternetConnection {
    try {
        $request = [System.Net.WebRequest]::Create("http://www.google.com")
        $response = $request.GetResponse()
        if ($response.StatusCode -eq 200) {
            #Write-Host "Internet connection is available."
            return
        }
    } catch {
        Write-Host "No internet connection." -ForegroundColor Red
        exit 2
        }
}

function Refresh-Environment {
    # Recharge les variables d'environnement pour la session PowerShell
    [System.Environment]::SetEnvironmentVariable('PATH', [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine), [System.EnvironmentVariableTarget]::Process)
    #Write-Host "Les variables d'environnement ont été rechargées pour la session actuelle." -ForegroundColor Green
}

function Install-Python {
    $pythonKey = "HKLM:\SOFTWARE\Python\PythonCore"
    if (Test-Path $pythonKey) {
        $pythonVersion = Get-ChildItem -Path $pythonKey | Sort-Object -Property PSChildName -Descending | Select-Object -First 1
        if ($pythonVersion.PSChildName -ge 3) {
            #Write-Host "Python version 3 or higher is already installed."
            return
        }
    }

    $pythonInstallerUrl = "https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe"
    $installerPath = "$TempFolderPath\python-installer.exe"

    try {
        Write-Host "Installing Python 3.9.7..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath
        Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        Remove-Item -Path $installerPath
        Write-Host "Python has been installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Python." -ForegroundColor Red
        exit 3
    }
}

function Download-Repo {
    # Définir l'URL du dépôt GitHub
    $RepoUrl = "https://github.com/1e0nn/The_Downloader/archive/refs/heads/main.zip"
    # Définir le chemin temporaire pour le téléchargement
    $ZipFile = Join-Path -Path $TempFolderPath -ChildPath "repo.zip"
    $ExtractPath = Join-Path -Path $TempFolderPath -ChildPath "ExtractedRepo"
    # Déplacer le contenu décompressé dans le répertoire courant
    $CurrentDirectory = Get-Location
    $ExtractedContentPath = Join-Path -Path $ExtractPath -ChildPath "The_Downloader-main"

    try {
        # Télécharger le fichier ZIP
        Write-Host "Téléchargement de l'archive du repository depuis $RepoUrl..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $RepoUrl -OutFile $ZipFile

        # Décompresser le contenu
        Write-Host "Décompression de l'archive..." -ForegroundColor Yellow
        if (Test-Path $ExtractPath) {
            Remove-Item -Path $ExtractPath -Recurse -Force
        }
        Expand-Archive -Path $ZipFile -DestinationPath $ExtractPath -Force | Out-Null

        if (Test-Path $ExtractedContentPath) {
            #Write-Host "Déplacement du contenu dans $CurrentDirectory..." -ForegroundColor Green
            Move-Item -Path (Join-Path $ExtractedContentPath '*') -Destination $CurrentDirectory -Force
        } else {
            Write-Host "Le dossier extrait n'a pas été trouvé. Vérifiez le contenu de l'archive." -ForegroundColor Red
            exit 4
        }
    } catch {
        Write-Host "Erreur : $($_.Exception.Message)" -ForegroundColor Red
        exit 5
    } finally {
        # Nettoyer les fichiers temporaires
        #Write-Host "Nettoyage des fichiers temporaires..." -ForegroundColor Yellow
        if (Test-Path $ZipFile) {
            Remove-Item -Path $ZipFile -Force
        }
        if (Test-Path $ExtractPath) {
            Remove-Item -Path $ExtractPath -Recurse -Force
        }

        # Déplace scdl.exe de dependencies vers TempFolderPath
        $scdlSourcePath = Join-Path -Path $Dependencies -ChildPath "scdl.exe"
        $scdlDestinationPath = Join-Path -Path $TempFolderPath -ChildPath "scdl.exe"
        Move-Item -Path $scdlSourcePath -Destination $scdlDestinationPath -Force
        #Write-Host "scdl.exe a été déplacé vers $TempFolderPath" -ForegroundColor Green

        Write-Host "L'archive a bien été téléchargé." -ForegroundColor Green

        # Installer les dépendances
        Unzip-ffmpeg
        Unzip-Whisper
        Install-VCRedist
        Refresh-Environment
        Install-Requirements -requirementsFile $requirementsFile

    }
}    


function Unzip-ffmpeg {
    
    # Chemins et URLs
    $SevenZipDownloadUrl = "https://www.7-zip.org/a/7z2301-x64.exe"  # Lien officiel de 7-Zip (version x64)
    $SevenZipPath = Join-Path -Path $TempFolderPath -ChildPath "7zip"
    $SevenZipExe = Join-Path -Path $SevenZipPath -ChildPath "7z.exe"
    $ArchivePath = Join-Path -Path (Get-Location) -ChildPath "dependencies/ffmpeg.zip"
    $ExtractPath = Join-Path -Path (Get-Location) -ChildPath "dependencies/"

    # Créer le dossier dependencies si nécessaire
    if (-Not (Test-Path $SevenZipPath)) {
        New-Item -ItemType Directory -Path $SevenZipPath | Out-Null
    }

    # Télécharger et extraire 7-Zip si non disponible
    if (-Not (Test-Path $SevenZipExe)) {
        try {
            Write-Host "Téléchargement de 7-Zip depuis $SevenZipDownloadUrl..." -ForegroundColor Yellow
            $TempInstallerPath = Join-Path -Path $SevenZipPath -ChildPath "7zip-installer.exe"
            Invoke-WebRequest -Uri $SevenZipDownloadUrl -OutFile $TempInstallerPath

            #Write-Host "Extraction de 7-Zip..." -ForegroundColor Green
            Start-Process -FilePath $TempInstallerPath -ArgumentList " /D=$SevenZipPath" -Wait

            # Vérifier que 7z.exe existe après extraction
            if (-Not (Test-Path $SevenZipExe)) {
                Throw "Échec de l'extraction de 7-Zip. Vérifiez l'installation."
                exit 6
            }

            # Supprimer l'installateur temporaire
            Remove-Item -Path $TempInstallerPath -Force
            Write-Host "7-Zip installé avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Erreur lors du téléchargement ou de l'installation de 7-Zip : $($_.Exception.Message)" -ForegroundColor Red
            exit 7
        }
    }

    # Extraire l'archive fractionnée avec 7-Zip
    try {
        Write-Host "Extraction de l'archive ffmpeg..." -ForegroundColor Yellow
        & $SevenZipExe x $ArchivePath -o"$ExtractPath" -y | Out-Null

        $ffmpegFolder = Join-Path -Path $ExtractPath -ChildPath "ffmpeg.exe"
        $destinationPath = "$TempFolderPath\ffmpeg.exe"

        if (Test-Path $destinationPath) {
            Remove-Item -Path $destinationPath -Recurse -Force
        }

        Move-Item -Path $ffmpegFolder -Destination $destinationPath -Force

        Write-Host "Extraction de ffmpeg réussi !" -ForegroundColor Green
        # Supprimer les fichiers dans dependencies qui commencent par ffmpeg.z
        $ffmpegFiles = Get-ChildItem -Path $ExtractPath -Filter "ffmpeg.z*"
        foreach ($file in $ffmpegFiles) {
            Remove-Item -Path $file.FullName -Force
        }
    } catch {
        Write-Host "Erreur pendant l'extraction de ffmpeg : $($_.Exception.Message)" -ForegroundColor Red
        exit 8
    }
}
function Unzip-Whisper {
    $zipFilePath = Join-Path -Path (Get-Location) -ChildPath "dependencies/whisper-main.zip"
    $extractPath = Join-Path -Path (Get-Location) -ChildPath "dependencies"


    try {
        Write-Host "Décompression de whisper-main.zip..." -ForegroundColor Yellow
        Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force | Out-Null

        Write-Host "whisper-main.zip a été décompressé avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Erreur pendant la décompression de whisper-main.zip : $($_.Exception.Message)" -ForegroundColor Red
        exit 11
    } finally {
        if (Test-Path $zipFilePath) {
            Remove-Item -Path $zipFilePath -Force
            #Write-Host "whisper-main.zip a été supprimé." -ForegroundColor Green
        }
    }
}

function Install-VCRedist {

    # Check if Visual C++ Redistributable is already installed
    $vcRedistKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    if (Test-Path $vcRedistKey) {
        $vcRedistInstalled = Get-ItemProperty -Path $vcRedistKey
        if ($vcRedistInstalled.Version -ge "14.0.0") {
            #Write-Host "Visual C++ Redistributable is already installed." -ForegroundColor Green
            return
        }
    }
    $vcRedistUrl = "https://aka.ms/vs/16/release/vc_redist.x64.exe"
    $installerPath = "$TempFolderPath\vc_redist.x64.exe"

    try {
        Write-Host "Installing Visual C++ Redistributable..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $vcRedistUrl -OutFile $installerPath
        Start-Process -FilePath $installerPath -ArgumentList "/quiet" -Wait
        Remove-Item -Path $installerPath
        Write-Host "Visual C++ Redistributable has been installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install Visual C++ Redistributable." -ForegroundColor Red
        exit 9
    }
}

# function Install-Requirements {
#     param(
#         [string]$requirementsFile
#     )

#     # Vérifier si le fichier requirements.txt existe
#     if (-Not (Test-Path $requirementsFile)) {
#         Write-Host "Le fichier $requirementsFile n'a pas été trouvé." -ForegroundColor Red
#         exit 10
#     }

#     # Vérifier si pip est installé
#     if (-Not (Get-Command pip -ErrorAction SilentlyContinue)) {
#         Write-Host "pip n'est pas installé. Veuillez installer pip avant de continuer." -ForegroundColor Red
#         exit 20
#     }

#     write-host "Installation des dépendances..." -ForegroundColor Yellow

#     # Lire les lignes du fichier requirements.txt
#     $requirements = Get-Content $requirementsFile


#     # Remplacer la ligne spécifique dans le fichier requirements.txt
#     $requirements = $requirements -replace "openai-whisper @ file:///./whisper-main", "openai-whisper @ file:///$Dependencies/whisper-main"
#     write-host "openai-whisper @ file:///$Dependencies/whisper-main" -ForegroundColor Cyan #A SUPRIMER

#     # Installer chaque dépendance
#     foreach ($requirement in $requirements) {
#         $requirement = $requirement.Trim()

#         if ($requirement) {
#             Write-Host "Installation de $requirement..." -ForegroundColor Yellow
#             try {
#                 # Exécuter la commande pip pour installer le paquet
#                 $result = pip install $requirement 2>&1
#                 if ($result -match "Successfully installed") {
#                     Write-Host "$requirement installé avec succès." -ForegroundColor Green
#                 } else {
#                     Write-Host "Erreur lors de l'installation de $requirement : $result" -ForegroundColor Red
#                 }
#             } catch {
#                 Write-Host "Erreur lors de l'installation de $requirement : $_" -ForegroundColor Red
#             }
#         }
#     }

#     Write-Host "Installation des dépendances terminée." -ForegroundColor Green
# }


function Install-Requirements {
    param(
        [string]$requirementsFile
    )

    # Vérifier si le fichier requirements.txt existe
    if (-Not (Test-Path $requirementsFile)) {
        Write-Host "Le fichier $requirementsFile n'a pas été trouvé." -ForegroundColor Red
        exit 10
    }

    # Vérifier si pip est installé
    if (-Not (Get-Command pip -ErrorAction SilentlyContinue)) {
        Write-Host "pip n'est pas installé. Veuillez installer pip avant de continuer." -ForegroundColor Red
        exit 20
    }

    write-host "Installation des dépendances:" -ForegroundColor Yellow

    # Lire les lignes du fichier requirements.txt
    $requirements = Get-Content $requirementsFile


    # Remplacer la ligne spécifique dans le fichier requirements.txt
    $whisperPATH = Join-Path -Path $Dependencies -ChildPath "whisper-main"
    $requirements = $requirements -replace "openai-whisper @ file:///./whisper-main", "openai-whisper @ file:///$whisperPATH"

    # Installer chaque dépendance
    foreach ($requirement in $requirements) {
        $requirement = $requirement.Trim()

        if ($requirement) {
            Write-Host "Installation de $requirement..." -ForegroundColor Yellow
            try {
                # Exécuter la commande pip pour installer le paquet
                $result = pip install $requirement 2>&1
                if ($result -match "Successfully installed") {
                    Write-Host "$requirement installé avec succès." -ForegroundColor Green
                } elseif ($result -match "Requirement already satisfied") {
                    Write-Host "$requirement est déjà installé." -ForegroundColor Green
                } else {
                    Write-Host "Erreur lors de l'installation de $requirement : $result" -ForegroundColor Red
                }
            } catch {
                Write-Host "Erreur lors de l'installation de $requirement : $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "Installation des dépendances terminée." -ForegroundColor Green
}

function Remove-dependencies {
    # Vérifie si le dossier dependencies existe et le supprime
    if (Test-Path $Dependencies) {
        Remove-Item -Path $Dependencies -Recurse -Force
        #Write-Host "Le dossier dependencies a été supprimé." -ForegroundColor Green
    }
}

# Début du script -----------------------------------------------------------------------------------------------

# Change to the directory where the script is located
Set-Location -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)

# Affiche le répertoire de travail actuel
#Write-Host "Current working directory: $(Get-Location)" -ForegroundColor Cyan

# Vérifier dossier path d'environnement existant
$TempFolderPath = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps" #-ChildPath "The_Downloader"
if (-Not (Test-Path $TempFolderPath)) {
    exit 100
    Write-Host "Le dossier $TempFolderPath n'existe pas." -ForegroundColor Red
} 

# Désactive les messages de progression afin de rendre rapide les téléchargements
$ProgressPreference = 'SilentlyContinue'

$Dependencies = Join-Path -Path (Get-Location) -ChildPath "dependencies/"
$requirementsFile = Join-Path -Path $Dependencies -ChildPath "requirements.txt"

Remove-dependencies

#Lance les fonctions de test
Test-AdminRights
Test-InternetConnection
Install-Python
Download-Repo
Remove-dependencies