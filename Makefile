.PHONY: image publish

image:
	docker build -f Dockerfile -t netangels/ddosguard:latest ./

publish:
	docker push netangels/ddosguard:latest
