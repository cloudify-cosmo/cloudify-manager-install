FROM cfy_manager_image

# this is the docker image started in CI; here we can add some hardening,
# so that we test an even stricter environment than we normally release

# normally secure_path contains /sbin:/bin:/usr/sbin:/usr/bin
# let's make it empty to test that we don't actually require any paths in it
# (set it to /none - I wasn't able to find a way to make an empty string work)
RUN sed -i 's/^Defaults    secure_path = .*/Defaults    secure_path = "\/none"/' /etc/sudoers
