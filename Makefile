all:
	moonc luaoauth1/*.moon spec/app.moon spec/test_config_methods.moon spec/test_helper_methods.moon
	chmod -R a+rX .
	luarocks make --pack-binary-rock *.rockspec
