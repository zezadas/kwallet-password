// highly based on https://github.com/KDE/kwallet-pam/blob/master/pam_kwallet.c
// This is a modification of the kwallet pam to be able to unlock the kde wallet
// with a password given from CLI at the style of keepass --pw-stdin

#include <gcrypt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <iostream>
#include <string>
#include <QDebug>

const static char *kwalletd = NULL;
const static char *kdehome = NULL;
const static char *socketPath = NULL;
const static char *envVar = "PAM_KWALLET5_LOGIN";
char *username;

#define KWALLET_PAM_KEYSIZE 56
#define KWALLET_PAM_SALTSIZE 56
#define KWALLET_PAM_ITERATIONS 50000

static int argumentsParsed = -1;
static void parseArguments(int argc, const char **argv) {
  // If already parsed
  if (argumentsParsed != -1) {
    return;
  }

  int x = 0;
  for (; x < argc; ++x) {
    if (strstr(argv[x], "kdehome=") != NULL) {
      kdehome = argv[x] + 8;
    } else if (strstr(argv[x], "kwalletd=") != NULL) {
      kwalletd = argv[x] + 9;
    } else if (strstr(argv[x], "socketPath=") != NULL) {
      socketPath = argv[x] + 11;
    }
    if (kdehome == NULL) {
      kdehome = ".local/share";
    }
    if (kwalletd == NULL) {
      kwalletd = "kwalletd5";
    }
  }
}

static int better_write(int fd, const char *buffer, int len) {
  size_t writtenBytes = 0;
  while (writtenBytes < len) {
    ssize_t result = write(fd, buffer + writtenBytes, len - writtenBytes);
    if (result < 0) {
      if (errno != EAGAIN && errno != EINTR) {
        return -1;
      }
    }
    writtenBytes += result;
  }

  return writtenBytes;
}

static int mkpath(char *path) {
  struct stat sb;
  char *slash;
  int done = 0;

  slash = path;

  while (!done) {
    slash += strspn(slash, "/");
    slash += strcspn(slash, "/");

    done = (*slash == '\0');
    *slash = '\0';

    if (stat(path, &sb)) {
      if (errno != ENOENT || (mkdir(path, 0777) && errno != EEXIST)) {
        qWarning("Couldn't create directory: %s because: %d-%s", path, errno,
                 strerror(errno));
        return (-1);
      }
    } else if (!S_ISDIR(sb.st_mode)) {
      return (-1);
    }

    *slash = '/';
  }

  return (0);
}

static void createNewSalt(const char *path) {
  // Don't re-create it if it already exists
  struct stat info;
  if (stat(path, &info) == 0 && info.st_size != 0 && S_ISREG(info.st_mode)) {
    return;
  }

  unlink(path); // in case the file already exists

  char *dir = strdup(path);
  dir[strlen(dir) - 14] = '\0'; // remove kdewallet.salt
  mkpath(dir); // create the path in case it does not exists
  free(dir);

  char *salt =
      (char *)gcry_random_bytes(KWALLET_PAM_SALTSIZE, GCRY_STRONG_RANDOM);
  const int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);

  // If the file can't be created
  if (fd == -1) {
    qWarning("Couldn't open file: %s because: %d-%s", path, errno,
             strerror(errno));
    exit(-2);
  }

  const ssize_t wlen = write(fd, salt, KWALLET_PAM_SALTSIZE);
  close(fd);
  if (wlen != KWALLET_PAM_SALTSIZE) {
    qWarning("Short write to file: %s", path);
    unlink(path);
    exit(-2);
  }

  return;
}

static int readSaltFile(char *path, char *saltOut) {
  struct stat info;
  if (stat(path, &info) != 0 || info.st_size == 0 || !S_ISREG(info.st_mode)) {
    qWarning("Failed to ensure %s looks like a salt file", path);
    free(path);
    return -1;
  }

  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    qWarning("Couldn't open file: %s because: %d-%s", path, errno,
             strerror(errno));
    free(path);
    return -1;
  }
  free(path);
  char salt[KWALLET_PAM_SALTSIZE] = {};
  const ssize_t readBytes = read(fd, saltOut, KWALLET_PAM_SALTSIZE);
  close(fd);
  if (readBytes != KWALLET_PAM_SALTSIZE) {
    qWarning("Couldn't read the full salt file contents from file. %d:%d",
             readBytes, KWALLET_PAM_SALTSIZE);
    exit(-1);
  }

  return 1;
}

int kwallet_hash(const char *passphrase, char *key) {
  if (!gcry_check_version("1.5.0")) {
    qWarning("kwalletd: libcrypt version is too old");
    return 1;
  }

  struct passwd *pw = getpwuid(getuid());
  const char *homefolder = pw->pw_dir;
  
  const char *fixpath = "kwalletd/kdewallet.salt";
  size_t pathSize = strlen(homefolder) + strlen(kdehome) + strlen(fixpath) +
                    3; // 3 == /, / and \0
  char *path = (char *)malloc(pathSize);
  sprintf(path, "%s/%s/%s", homefolder, kdehome, fixpath);

  createNewSalt(path);

  char salt[KWALLET_PAM_SALTSIZE] = {};
  const int readSaltSuccess = readSaltFile(path, salt);

  // free(path);
  if (!readSaltSuccess) {
    qWarning("kwalletd: Couldn't create or read the salt file");
    return 1;
  }

  gcry_error_t error;

  /* We cannot call GCRYCTL_INIT_SECMEM as it drops privileges if getuid() !=
  geteuid().
   * PAM modules are in many cases executed through setuid binaries, which this
  call
   * would break.
   * It was never effective anyway as neither key nor passphrase are in secure
  memory,
   * which is a prerequisite for secure operation...
  error = gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0);
  if (error != 0) {
      free(salt);
      syslog(LOG_ERR, "%s-kwalletd: Can't get secure memory: %d", logPrefix,
  error);
      return 1;
  }
  */

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  error = gcry_kdf_derive(passphrase, strlen(passphrase), GCRY_KDF_PBKDF2,
                          GCRY_MD_SHA512, salt, KWALLET_PAM_SALTSIZE,
                          KWALLET_PAM_ITERATIONS, KWALLET_PAM_KEYSIZE, key);

  return (int)error; // gcry_kdf_derive returns 0 on success
}

static const char *get_env(const char *name) {
  const char *env;

  env = getenv(name);
  if (env != NULL) {
    return env;
  }

  return NULL;
}

static void execute_kwallet(int toWalletPipe[2], char *fullSocket) {
  // In the child pam_syslog does not work, using syslog directly
  // keep stderr open so socket doesn't returns us that fd
  int x = 3;
  // Close fd that are not of interest of kwallet
  for (; x < 64; ++x) {
    if (x != toWalletPipe[0]) {
      close(x);
    }
  }

  // This is the side of the pipe PAM will send the hash to
  close(toWalletPipe[1]);

  int envSocket;
  if ((envSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    qWarning("couldn't create socket");
    free(fullSocket);
    return;
  }

  struct sockaddr_un local;
  local.sun_family = AF_UNIX;

  if (strlen(fullSocket) > sizeof(local.sun_path)) {
    qWarning("socket path %s too long to open", fullSocket);
    free(fullSocket);
    return;
  }
  strcpy(local.sun_path, fullSocket);
  free(fullSocket);
  fullSocket = NULL;
  unlink(local.sun_path); // Just in case it exists from a previous login

  qWarning("final socket path: %s", local.sun_path);

  size_t len = strlen(local.sun_path) + sizeof(local.sun_family);
  if (bind(envSocket, (struct sockaddr *)&local, len) == -1) {
    qWarning("kwalletd: Couldn't bind to local file\n");
    return;
  }

  if (listen(envSocket, 5) == -1) {
    qWarning("kwalletd: Couldn't listen in socket\n");
    return;
  }

  // COMMENT THIS LINE IF YOU WANT OUTPUT
  // finally close stderr
  close(2);

  // Fork twice to daemonize kwallet
  setsid();
  pid_t pid = fork();
  if (pid != 0) {
    if (pid == -1) {
      exit(EXIT_FAILURE);
    } else {
      exit(0);
    }
  }

  // TODO use a pam argument for full path kwalletd
  char pipeInt[4];
  sprintf(pipeInt, "%d", toWalletPipe[0]);
  char sockIn[4];
  sprintf(sockIn, "%d", envSocket);

  char *args[] = {
      strdup(kwalletd), (char *)"--pam-login", pipeInt, sockIn, NULL, NULL};
  execvp(args[0], args);
  // execve(args[0], args, envp);

  qWarning("could not execute kwalletd from %s", kwalletd);
  // close(2);
}

static void start_kwallet(const char *kwalletKey) {
  // Just in case we get broken pipe, do not break the pam process..
  struct sigaction sigPipe, oldSigPipe;
  memset(&sigPipe, 0, sizeof(sigPipe));
  memset(&oldSigPipe, 0, sizeof(oldSigPipe));
  sigPipe.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sigPipe, &oldSigPipe);

  int toWalletPipe[2] = {-1, -1};
  if (pipe(toWalletPipe) < 0) {
    qWarning("Couldn't create pipes");
  }

  const char *socketPrefix = "kwallet5";

  char *fullSocket = NULL;
  if (socketPath) {
    size_t needed = snprintf(NULL, 0, "%s/%s_%s%s", socketPath, socketPrefix,
                             username, ".socket");
    needed += 1;
    fullSocket = (char *)malloc(needed);
    snprintf(fullSocket, needed, "%s/%s_%s%s", socketPath, socketPrefix,
             username, ".socket");
  } else {
    socketPath = get_env("XDG_RUNTIME_DIR");
    if (socketPath) {
      size_t needed =
          snprintf(NULL, 0, "%s/%s%s", socketPath, socketPrefix, ".socket");
      needed += 1;
      fullSocket = (char *)malloc(needed);
      snprintf(fullSocket, needed, "%s/%s%s", socketPath, socketPrefix,
               ".socket");
    } else {
      size_t needed =
          snprintf(NULL, 0, "/tmp/%s_%s%s", socketPrefix, username, ".socket");
      needed += 1;
      fullSocket = (char *)malloc(needed);
      snprintf(fullSocket, needed, "/tmp/%s_%s%s", socketPrefix, username,
               ".socket");
    }
  }

  setenv(envVar,fullSocket,1); // does overwrite
  
  pid_t pid;
  int status;
  switch (pid = fork()) {
  case -1:
    qWarning("Couldn't fork to execv kwalletd");
    return;

  // Child fork, will contain kwalletd
  case 0:
    execute_kwallet(toWalletPipe, fullSocket);
    /* Should never be reached */
    break;

  // Parent
  default:
    waitpid(pid, &status, 0);
    if (status != 0) {
      qWarning("Couldn't fork to execv kwalletd");
      return;
    }
    break;
  };

  close(toWalletPipe[0]); // Read end of the pipe, we will only use the write
  if (better_write(toWalletPipe[1], kwalletKey, KWALLET_PAM_KEYSIZE) < 0) {
    qWarning("Impossible to write walletKey to walletPipe");
    return;
  }

  close(toWalletPipe[1]);

  int fd, rc;
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  strncpy(addr.sun_path, fullSocket, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("connect error");
    exit(-1);
  }

  close(fd);
}

int main(int argc, const char **argv) {
  parseArguments(argc, argv);

  uid_t uid = geteuid();
  struct passwd *pw = getpwuid(uid);
  if (pw) {
    username = pw->pw_name;
  }

  const char *password;
  std::string strpass;
  std::getline(std::cin, strpass);
  password = strpass.c_str();
  qWarning() << strpass.c_str();

  if (!username) {
    qWarning("Couldn't get username (it is empty)");
  }

  if (!password) {
    qWarning("Couldn't get password (it is empty)");
  }

  char *key = (char *)malloc(KWALLET_PAM_KEYSIZE);
  if (!key || kwallet_hash(password, key) != 0) {
    free(key);
    qWarning("Fail into creating the hash");
    return 1;
  }

  start_kwallet(key);

  return 0;
}
