This folder contains a sample inspector that can be used as a template
for your own inspector.

Copy the contents (excluding this file) to a new folder, search and replace:

 - my_plugin_name with the name of your plugin
 - [RANDOM_32BIT_HEX_NUMBER] with a unique randomly generated hex number,
   where every instance in a given file uses the same number

Also search for TODO's in the files and follow the instructions.

Remember to update: ../snort_plugins.cc (to make snort aware of the plugin)
Remember to update: ../../plugins.list (to make the build system aware of the plugin)

If you have sh3 automated tests for your plugin in a tests folder, you
should also update ../../sh3_tests.list
