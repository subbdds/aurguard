pkgname=aurguard-git
pkgver=0.1.0.r0.gc4d4d64
pkgrel=1
pkgdesc='A yay/paru wrapper that scans AUR build files before installation'
arch=('any')
url='https://github.com/subbdds/aurguard'
depends=('python' 'pacman')
makedepends=('git' 'python-build' 'python-installer' 'python-setuptools' 'python-wheel')
optdepends=(
  'yay: use yay as the wrapped AUR helper'
  'paru: use paru as the wrapped AUR helper'
)
provides=('aurguard')
conflicts=('aurguard')
source=('aurguard::git+https://github.com/subbdds/aurguard.git')
sha256sums=('SKIP')

pkgver() {
  cd aurguard
  printf '0.1.0.r%s.g%s' "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd aurguard
  python -m build --wheel --no-isolation
}

package() {
  cd aurguard
  python -m installer --destdir="$pkgdir" dist/*.whl
}
