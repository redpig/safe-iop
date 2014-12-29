#
# safe_iop - Makefile
#
# Author:: Will Drewry <redpig@dataspill.org>
# Copyright 2007 redpig@dataspill.org
#
# Unless required by applicable law or agreed to in writing, software
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied.
#

os=$(shell uname -o)

_all::
%::
	@# Check for non GNU/Linux
	@(echo '$(os)' | grep -vq "GNU/Linux" && \
          echo "Use 'make -f Makefile.<your_make>'" && exit 1) || true
	@echo 'Building for GNU platform: $(os)'
	@make -f Makefile.gnu MAKEFLAGS=$(MAKEFLAGS) $(MAKECMDGOALS)
