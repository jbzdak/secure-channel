# coding=utf-8

from invoke import task


@task
def pep8(ctx):
  ctx.run("pep8 secure_channel secure_channel_test")


@task
def lint(ctx):
  ctx.run("pylint secure_channel secure_channel_test -r n")


@task
def test(ctx):
  ctx.run("py.test -v --cov secure_channel --cov-report=html --cov-report=term-missing secure_channel_test")


@task(pre=[test, pep8, lint])
def check(ctx):
  pass




