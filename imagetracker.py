class ImageTracker(object):
	def __init__(self):
		self.images = dict()

	def mark_observed_image(self, cur_id, image):
		if cur_id not in self.images:
			self.images[cur_id] = list()
		cur_images = self.images[cur_id]

		for other, pre_ids in cur_images:
			if image == other:
				# add the pre_id to the same image
				pre_ids.add(image.block_id)
				return True
		# keep one full copy is enough
		cur_images.append((image, {image.block_id}))
		return False

	def get_observed_image(self, cur_id, pre_id=None):
		if cur_id not in self.images:
			return None
		cur_images = self.images[cur_id]
		if not pre_id:  # just return one
			return cur_images[0][0]
		for image, pre_ids in cur_images:
			if pre_id in pre_ids:
				return image
		return None

	def get_observed_images(self, cur_id):
		if cur_id not in self.images:
			return None
		images = list()
		for image, _ in self.images[cur_id]:
			images.append(image)
		return images
