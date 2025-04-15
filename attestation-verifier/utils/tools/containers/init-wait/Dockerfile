#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim
COPY init-wait/entrypoint.sh /entrypoint.sh

# Add a user and switch to it
USER tc-agnet

CMD ["/entrypoint.sh"]
